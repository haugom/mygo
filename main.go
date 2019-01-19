package main

import (
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/haugom/gwp/mygo/config"
	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	prommiddleware "github.com/slok/go-prometheus-middleware"
	promnegroni "github.com/slok/go-prometheus-middleware/negroni"
	"github.com/urfave/negroni"
	"github.com/xyproto/permissions2"
	"golang.org/x/oauth2"
	"gopkg.in/boj/redistore.v1"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	GitCommit 		string 	= ""
	BuildDate    	string 	= ""
	Version			string 	= ""
	srvAddr     	string 	= ":3001"
	metricsAddr 	string	= ":8081"
)

var Store *redistore.RediStore

type auth0profilemap map[string]interface{}
type auth0profile struct {
	Data auth0profilemap
}

type key int
const stateKey key = 0

type SessionState struct {
	userstate *permissions.Permissions
}

func (c *SessionState) attachStateToContext(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), stateKey, c.userstate)
		h.ServeHTTP(rw, req.WithContext(ctx))
	})
}

func stateFromContext(ctx context.Context) *permissions.Permissions {
	return ctx.Value(stateKey).(*permissions.Permissions)
}

func main() {

	_ = "breakpoint"
	log.Printf("This is version %s, commit: %s, build date: %s\n", Version, GitCommit, BuildDate)

	environment := flag.String("e", "development", "")
	flag.Usage = func() {
		fmt.Println("Usage: main -e {mode}")
		os.Exit(1)
	}
	flag.Parse()
	config.Init(*environment)
	databaseHost := config.GetConfig().GetString("REDIS_HOST")
	log.Printf("Redis-cache at: %s\n", databaseHost)

	// Create our middleware.
	promMiddleware := prommiddleware.NewDefault()

	// New permissions middleware
	perm, err := permissions.NewWithRedisConf2(0, databaseHost)
	if err != nil {
		log.Fatalln(err)
	}

	gob.Register(&auth0profile{})

	// Fetch new store.
	store, err := redistore.NewRediStoreWithDB(10, "tcp", databaseHost, "", "1", []byte(config.GetConfig().GetString("REDIS_KEY")))
	if err != nil {
		panic(err)
	}
	defer store.Close()
	gob.Register(map[string]interface{}{})
	Store = store
	log.Printf("%v\n", Store)

	// Get the userstate, used in the handlers below
	sessionState := SessionState{perm}

	stdChain := alice.New(sessionState.attachStateToContext)

	// Create our router.
	mux := http.NewServeMux()

	// Create our negroni instance.
	n := negroni.Classic()

	// Add the middleware to negroni.
	n.Use(promnegroni.Handler("", promMiddleware))
	// Enable the permissions middleware
	n.Use(perm)

	// Finally set our router on negroni.
	n.UseHandler(mux)

	files := http.FileServer(http.Dir("public"))
	mux.Handle("/public/", http.StripPrefix("/public/", files))

	mux.Handle("/", stdChain.Then(http.HandlerFunc(index)))
	mux.Handle("/register", stdChain.Then(http.HandlerFunc(register)))
	mux.Handle("/confirm", stdChain.Then(http.HandlerFunc(confirm)))
	mux.Handle("/remove", stdChain.Then(http.HandlerFunc(remove)))
	mux.Handle("/login", stdChain.Then(http.HandlerFunc(login)))
	mux.Handle("/logout", stdChain.Then(http.HandlerFunc(logout)))
	mux.Handle("/makeadmin", stdChain.Then(http.HandlerFunc(makeadmin)))
	mux.Handle("/clear", stdChain.Then(http.HandlerFunc(clear)))
	mux.Handle("/data", stdChain.Then(http.HandlerFunc(data)))
	mux.Handle("/admin", stdChain.Then(http.HandlerFunc(admin)))
	mux.Handle("/callback", stdChain.Then(http.HandlerFunc(callback)))
	mux.Handle("/login2", stdChain.Then(http.HandlerFunc(auth0Login)))
	mux.Handle("/home", stdChain.Then(http.HandlerFunc(home)))
	mux.Handle("/user", stdChain.Then(http.HandlerFunc(user)))
	mux.Handle("/logout2", stdChain.Then(http.HandlerFunc(auth0Logout)))
	perm.SetDenyFunction(http.HandlerFunc(deny))
	mux.HandleFunc(`/notfound`, notfound)
	mux.HandleFunc(`/ok`, hello)

	// Serve content
	go startServer(n)

	// Serve our metrics.
	go startMetrics()

	// Wait until some signal is captured.
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGTERM, syscall.SIGINT)
	<-sigC
}

func index(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintf(w, "Welcome to the home page!\n\n")

	userstate := stateFromContext(r.Context()).UserState()

	fmt.Fprintf(w, "Has user bob: %v\n", userstate.HasUser("bob"))
	fmt.Fprintf(w, "Logged in on server: %v\n", userstate.IsLoggedIn("bob"))
	fmt.Fprintf(w, "Is confirmed: %v\n", userstate.IsConfirmed("bob"))
	fmt.Fprintf(w, "Username stored in cookies (or blank): %v\n", userstate.Username(r))
	fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *user rights*: %v\n", userstate.UserRights(r))
	fmt.Fprintf(w, "Current user is logged in, has a valid cookie and *admin rights*: %v\n", userstate.AdminRights(r))
	fmt.Fprintf(w, "\nTry: /register, /confirm, /remove, /login, /logout, /makeadmin, /clear, /data and /admin")

	store := Store

	// Get a session.
	session, err := store.Get(r, "session-key")
	if err != nil {
		log.Fatal(err.Error())
	}

	// Save.
	if err = sessions.Save(r, w); err != nil {
		log.Fatalf("Error saving session: %v", err)
	}

	// Delete session.
	session.Options.MaxAge = -1
	if err = sessions.Save(r, w); err != nil {
		log.Fatalf("Error saving session: %v", err)
	}

	// Change session storage configuration for MaxAge = 10 days.
	store.SetMaxAge(10 * 24 * 3600)

}

func register(w http.ResponseWriter, r *http.Request) {
	userstate := stateFromContext(r.Context()).UserState()
	userstate.AddUser("bob", "hunter1", "bob@zombo.com")
	fmt.Fprintf(w, "User bob was created: %v\n", userstate.HasUser("bob"))
}

func confirm(w http.ResponseWriter, r *http.Request) {
	userstate := stateFromContext(r.Context()).UserState()
	userstate.MarkConfirmed("bob")
	fmt.Fprintf(w, "User bob was confirmed: %v\n", userstate.IsConfirmed("bob"))
}

func remove(w http.ResponseWriter, r *http.Request) {
	userstate := stateFromContext(r.Context()).UserState()
	userstate.RemoveUser("bob")
	fmt.Fprintf(w, "User bob was removed: %v\n", !userstate.HasUser("bob"))
}

func login(w http.ResponseWriter, r *http.Request) {
	userstate := stateFromContext(r.Context()).UserState()
	userstate.Login(w, "bob")
	fmt.Fprintf(w, "bob is now logged in: %v\n", userstate.IsLoggedIn("bob"))
}

func logout(w http.ResponseWriter, r *http.Request) {
	userstate := stateFromContext(r.Context()).UserState()
	userstate.Logout("bob")
	fmt.Fprintf(w, "bob is now logged out: %v\n", !userstate.IsLoggedIn("bob"))
}

func makeadmin(w http.ResponseWriter, r *http.Request) {
	userstate := stateFromContext(r.Context()).UserState()
	userstate.SetAdminStatus("bob")
	fmt.Fprintf(w, "bob is now administrator: %v\n", userstate.IsAdmin("bob"))
}

func clear(w http.ResponseWriter, r *http.Request) {
	userstate := stateFromContext(r.Context()).UserState()
	userstate.ClearCookie(w)
	fmt.Fprintf(w, "Clearing cookie")
}

func data(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "user page that only logged in users must see!")
}

func admin(w http.ResponseWriter, r *http.Request) {
	userstate := stateFromContext(r.Context()).UserState()
	fmt.Fprintf(w, "super secret information that only logged in administrators must see!\n\n")
	if usernames, err := userstate.AllUsernames(); err == nil {
		fmt.Fprintf(w, "list of all users: "+strings.Join(usernames, ", "))
	}
}

func deny(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Permission denied!", http.StatusForbidden)
}

func xxx(w http.ResponseWriter, r *http.Request) {
	userstate := stateFromContext(r.Context()).UserState()
	fmt.Fprintf(w, "User bob was confirmed: %v\n", userstate.IsConfirmed("bob"))
}

func hello(w http.ResponseWriter, r *http.Request) {
	sleep := rand.Intn(1999) + 1
	time.Sleep(time.Duration(sleep) * time.Millisecond)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "slept %d milliseconds\n", sleep)
}

func notfound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintln(w, "not found")
}

func callback(w http.ResponseWriter, r *http.Request) {
	domain := "haugom.eu.auth0.com"

	conf := &oauth2.Config{
		ClientID:     config.GetConfig().GetString("CLIENT_ID"),
		ClientSecret: config.GetConfig().GetString("CLIENT_SECRET"),
		RedirectURL:  config.GetConfig().GetString("CALLBACK"),
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + domain + "/authorize",
			TokenURL: "https://" + domain + "/oauth/token",
		},
	}
	state := r.URL.Query().Get("state")
	session, err := Store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if state != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusInternalServerError)
		return
	}

	code := r.URL.Query().Get("code")

	token, err := conf.Exchange(context.TODO(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Getting now the userInfo
	client := conf.Client(context.TODO(), token)
	resp, err := client.Get("https://" + domain + "/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	var profile auth0profilemap
	if err = json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profilemap:= auth0profile{profile}

	session, err = Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["id_token"] = token.Extra("id_token")
	session.Values["access_token"] = token.AccessToken
	session.Values["profile"] = profilemap
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to logged in page
	http.Redirect(w, r, "/user", http.StatusSeeOther)

}

func auth0Login(w http.ResponseWriter, r *http.Request) {
	domain := "haugom.eu.auth0.com"
	aud := "mygo2"

	conf := &oauth2.Config{
		ClientID:     config.GetConfig().GetString("CLIENT_ID"),
		ClientSecret: config.GetConfig().GetString("CLIENT_SECRET"),
		RedirectURL:  config.GetConfig().GetString("CALLBACK"),
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + domain + "/authorize",
			TokenURL: "https://" + domain + "/oauth/token",
		},
	}

	if aud == "" {
		aud = "https://" + domain + "/userinfo"
	}

	// Generate random state
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, err := Store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audience := oauth2.SetAuthURLParam("audience", aud)
	url := conf.AuthCodeURL(state, audience)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func home(w http.ResponseWriter, r *http.Request) {
	templates := template.Must(template.ParseFiles("templates/home.html"))
	e := templates.ExecuteTemplate(w, "home.html", "")
	if e != nil {
		log.Println(e)
	}
}

func user(w http.ResponseWriter, r *http.Request) {
	templates := template.Must(template.ParseFiles("templates/user.html"))

	session, err := Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	val := session.Values["profile"]
	var profile = &auth0profile{}
	var templeateData = auth0profilemap{}
	if p, ok := val.(*auth0profile); !ok {
		// Handle the case that it's not an expected type
		log.Println("NOT OK")
		templeateData["loggedin"] = false
		//log.Println(profile)
	} else {
		log.Println("IS OK")
		log.Println(profile.Data)
		profile = p
		templeateData["loggedin"] = true
		templeateData["picture"] = profile.Data["picture"]
		templeateData["nickname"] = profile.Data["nickname"]
		templeateData["roles"] = profile.Data["https://haugom.org/roles"]
	}



	e := templates.ExecuteTemplate(w, "user.html", templeateData)
	if e != nil {
		log.Println(e)
	}
}

func auth0Logout(w http.ResponseWriter, r *http.Request) {
	domain := "haugom.eu.auth0.com"

	session, err2 := Store.Get(r, "auth-session")
	if err2 != nil {
		http.Error(w, err2.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["profile"] = ""

	var Url *url.URL
	Url, err := url.Parse("https://" + domain)

	if err != nil {
		panic("boom")
	}

	Url.Path += "/v2/logout"
	parameters := url.Values{}
	parameters.Add("returnTo", config.GetConfig().GetString("HOME"))
	parameters.Add("client_id", config.GetConfig().GetString("CLIENT_ID"))
	Url.RawQuery = parameters.Encode()

	http.Redirect(w, r, Url.String(), http.StatusTemporaryRedirect)
}

func startServer(handler http.Handler) {
	log.Printf("server listening at %s", srvAddr)
	if err := http.ListenAndServe(srvAddr, handler); err != nil {
		log.Panicf("error while serving: %s", err)
	}
}

func startMetrics() {
	log.Printf("metrics listening at %s", metricsAddr)
	if err := http.ListenAndServe(metricsAddr, promhttp.Handler()); err != nil {
		log.Panicf("error while serving metrics: %s", err)
	}

}