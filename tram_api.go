package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"time"
	// "encoding/json"
	"github.com/kravitz/tram_api/tram-commons/db"
	"github.com/kravitz/tram_api/tram-commons/model"
	"github.com/kravitz/tram_api/tram-commons/util"
	"github.com/kravitz/tram_api/tram-commons/web"

	"golang.org/x/crypto/bcrypt"

	"github.com/streadway/amqp"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const saltSize int = 8

type tramAPIApp struct {
	QCon           *amqp.Connection
	MgoSession     *mgo.Session
	UsernameRegexp *regexp.Regexp
}

const (
	errorUsernameTooShort      = "ERROR_USERNAME_TOO_SHORT"
	errorUsernameBadCharacters = "ERROR_USERNAME_BAD_CHARACTERS"
	errorPasswordTooShort      = "ERROR_PASSWORD_TOO_SHORT"
	errorUserExists            = "ERROR_USER_EXISTS"
	errorBadPasswordOrUsername = "ERROR_BAD_PASSWORD_OR_USERNAME"
	errorBadSid                = "ERROR_BAD_SID"
	errorFileNotFound          = "ERROR_FILE_NOT_FOUND"
	errorTaskNotFound          = "ERROR_TASK_NOT_FOUND"
)

// TODO 1: Storage location

func (app *tramAPIApp) uploadComputationData(response bson.M, req *http.Request) {
	sid := req.FormValue("sid")
	s := app.MgoSession.Copy()
	defer s.Close()
	session := &model.Session{}
	err := db.GetCol(s, "sessions").Find(bson.M{"sid": sid}).One(session)
	if err != nil {
		log.Fatal(err) // stub
	}
	fid := app.uploadFile(req, "file", "data", session.Username)

	response["status"] = "ok"
	response["id"] = fid
}

func (app *tramAPIApp) uploadControlScript(response bson.M, req *http.Request) {
	sid := req.FormValue("sid")
	s := app.MgoSession.Copy()
	defer s.Close()
	session := &model.Session{}
	err := db.GetCol(s, "sessions").Find(bson.M{"sid": sid}).One(session)
	if err != nil {
		log.Fatal(err) // stub
	}
	fid := app.uploadFile(req, "file", "control", session.Username)

	response["status"] = "ok"
	response["id"] = fid
}

// TODO make fixed type return
func (app *tramAPIApp) uploadFile(req *http.Request, formFile string, collection string, owner string) interface{} {
	file, header, err := req.FormFile(formFile)

	if err != nil {
		log.Println(err)
		return nil
	}

	defer file.Close()

	s := app.MgoSession.Copy()
	defer s.Close()
	fs := db.GetGridFS(s, collection)
	out, _ := fs.Create("")
	defer out.Close()

	fd := &model.FileDescription{Filename: header.Filename, Owner_Username: owner}
	out.SetMeta(fd)
	_, err = io.Copy(out, file)
	if err != nil {
		log.Println(err)
		return nil
	}

	log.Println("Succesfully uploaded file: " + header.Filename)
	return out.Id()
}

func (app *tramAPIApp) usernameValidator(username string) string {
	if len(username) < 4 {
		return errorUsernameTooShort
	}
	if !app.UsernameRegexp.MatchString(username) {
		return errorUsernameBadCharacters
	}
	return ""
}

func passwordValidator(password string) string {
	if len(password) < 6 {
		return errorPasswordTooShort
	}
	return ""
}

func getSid() string {
	bytes := make([]byte, 16, 16)
	io.ReadFull(rand.Reader, bytes)
	sid, _ := bcrypt.GenerateFromPassword(bytes, bcrypt.DefaultCost)
	return string(sid)
}

func (app *tramAPIApp) getUserSession(username string) *model.Session {
	s := app.MgoSession.Copy()
	defer s.Close()

	success := false
	session := &model.Session{}
	for !success {
		success = true
		err := db.GetCol(s, "sessions").Find(bson.M{"username": username}).One(session)
		if err != nil {
			success = false
			session.Username = username
			session.CreatedAt = time.Now()
			session.Sid = getSid()
			err = db.GetCol(s, "sessions").Insert(session)
			if err != nil {
				success = false
				if !mgo.IsDup(err) {
					log.Fatal(err)
				}
			}
		}
	}

	return session
}

func putError(response bson.M, err string) {
	response["status"] = "error"
	response["error"] = err
}

func (app *tramAPIApp) userRegister(response bson.M, req *http.Request) {
	username := req.FormValue("username")
	password := req.FormValue("password")
	email := req.FormValue("email")

	response["status"] = "ok"

	err := app.usernameValidator(username)
	if err != "" {
		putError(response, err)
		return
	}
	err = passwordValidator(password)
	if err != "" {
		putError(response, err)
		return
	}
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &model.User{
		Username: username,
		Email:    email,
		Password: passwordHash,
		Dor:      time.Now(),
		Banned:   false,
	}

	s := app.MgoSession.Copy()
	defer s.Close()

	c := db.GetCol(s, "users")
	mgoErr := c.Insert(user)
	if mgoErr != nil {
		if mgo.IsDup(mgoErr) {
			putError(response, errorUserExists)
			return
		}
		log.Fatal(mgoErr)
	}

	userSession := app.getUserSession(username)
	response["sid"] = userSession.Sid

	log.Println(fmt.Sprintf("Register user: %v", util.Qjson(user)))
	log.Println(fmt.Sprintf("His session is: %v", util.Qjson(userSession)))
}

func (app *tramAPIApp) retrieveUserSession(s *mgo.Session, sid string) (session *model.Session) {
	session = &model.Session{}
	err := db.GetCol(s, "sessions").Find(bson.M{"sid": sid}).One(session)
	if err != nil {
		if err == mgo.ErrNotFound {
			session = nil
		} else {
			log.Fatal(err)
		}
	}
	return session
}

func (app *tramAPIApp) getUserInfo(response bson.M, req *http.Request) {
	sid := req.FormValue("sid")
	s := app.MgoSession.Copy()
	defer s.Close()

	session := app.retrieveUserSession(s, sid)
	if session == nil {
		putError(response, errorBadSid)
		return
	}
	user := &model.User{}
	db.GetCol(s, "users").Find(bson.M{"username": session.Username}).One(user)
	response["status"] = "ok"
	response["user"] = bson.M{
		"username": user.Username,
		"email":    user.Email,
		"dor":      user.Dor,
	}
}

func (app *tramAPIApp) logout(response bson.M, req *http.Request) {
	sid := req.FormValue("sid")

	s := app.MgoSession.Copy()
	defer s.Close()

	s.DB("tram").C("sessions").Remove(bson.M{"sid": sid})
	response["status"] = "ok"
}

func (app *tramAPIApp) login(response bson.M, req *http.Request) {
	username := req.FormValue("username")
	password := req.FormValue("password")
	response["status"] = "ok"

	s := app.MgoSession.Copy()
	defer s.Close()

	user := &model.User{}
	err := db.GetCol(s, "users").Find(bson.M{"username": username}).One(user)
	if err != nil || bcrypt.CompareHashAndPassword(user.Password, []byte(password)) != nil {
		putError(response, errorBadPasswordOrUsername)
		return
	}

	userSession := app.getUserSession(username)
	response["sid"] = userSession.Sid
	log.Println(fmt.Sprintf("User login: %v", user.Username))
}

func (app *tramAPIApp) removeUploadedData(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	dfid := r.FormValue("data_file_id")

	s := app.MgoSession.Copy()
	defer s.Close()

	session := app.retrieveUserSession(s, sid)
	if session == nil {
		putError(response, errorBadSid)
		return
	}

	meta := getFileMeta(s, "data", dfid)
	if meta == nil || meta.Owner_Username != session.Username {
		putError(response, errorFileNotFound)
		return
	}

	db.GetGridFS(s, "data").RemoveId(bson.ObjectIdHex(dfid))
	response["status"] = "ok"
}

func (app *tramAPIApp) removeUploadedControl(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	cfid := r.FormValue("control_file_id")

	s := app.MgoSession.Copy()
	defer s.Close()

	session := app.retrieveUserSession(s, sid)
	if session == nil {
		putError(response, errorBadSid)
		return
	}

	meta := getFileMeta(s, "control", cfid)
	if meta == nil || meta.Owner_Username != session.Username {
		putError(response, errorFileNotFound)
		return
	}

	db.GetGridFS(s, "control").RemoveId(bson.ObjectIdHex(cfid))
	response["status"] = "ok"
}

type fileMetaTemp struct {
	Metadata *model.FileDescription
}

func getFileMeta(s *mgo.Session, fsName string, fileID string) *model.FileDescription {
	fs := db.GetGridFS(s, fsName)
	result := fileMetaTemp{}
	err := fs.Find(bson.M{"_id": bson.ObjectIdHex(fileID)}).One(&result)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil
		}
		log.Fatal(err)
	}
	return result.Metadata
}

func (app *tramAPIApp) enqueueExecute(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	dfid := r.FormValue("data_file_id")
	cfid := r.FormValue("control_file_id")

	s := app.MgoSession.Copy()
	defer s.Close()
	session := app.retrieveUserSession(s, sid)
	if session == nil {
		putError(response, errorBadSid)
		return
	}

	dfd := getFileMeta(s, "data", dfid)
	if dfd == nil {
		putError(response, errorFileNotFound)
		return
	}
	cfd := getFileMeta(s, "control", cfid)
	if cfd == nil {
		putError(response, errorFileNotFound)
	}

	if dfd.Owner_Username != session.Username || cfd.Owner_Username != session.Username {
		putError(response, errorFileNotFound)
		return
	}

	ch, errCh := app.QCon.Channel()
	if errCh != nil {
		log.Fatal(errCh)
	}
	defer ch.Close()
	tasks := db.GetCol(s, "tasks")
	task := model.Task{
		Id:         bson.NewObjectId(),
		Output:     "",
		Status:     model.TASK_STATUS_PENDING,
		Owner:      session.Username,
		DataFid:    dfid,
		ControlFid: cfid,
	}
	err := tasks.Insert(&task)
	if err != nil {
		log.Fatal(err)
	}
	msg := model.TaskMsg{
		TaskId:     task.Id,
		DataFid:    dfid,
		ControlFid: cfid,
	}
	bMsg, errM := bson.Marshal(&msg)
	if errM != nil {
		log.Fatal(errM)
	}
	err = ch.Publish("workers", "task", true, false, amqp.Publishing{
		Headers:         amqp.Table{},
		ContentType:     "application/json",
		ContentEncoding: "UTF-8",
		Body:            bMsg,
		DeliveryMode:    amqp.Persistent,
	})
	if err != nil {
		log.Fatal(err)
	}

	response["status"] = "ok"
	response["task_id"] = task.Id
}

func (app *tramAPIApp) getTaskStatus(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	taskID := r.FormValue("task_id")
	s := app.MgoSession.Copy()
	defer s.Close()
	session := app.retrieveUserSession(s, sid)
	if session == nil {
		putError(response, errorBadSid)
		return
	}

	task := model.Task{}
	err := db.GetCol(s, "tasks").Find(bson.M{"_id": bson.ObjectIdHex(taskID)}).One(&task)
	if err != nil {
		log.Fatal(err)
	}
	if task.Owner != session.Username {
		putError(response, errorTaskNotFound)
		return
	}
	response["task"] = task
}

func (app *tramAPIApp) fetchFilesMeta(filestype string, sid string, response bson.M) {
	s := app.MgoSession.Copy()
	defer s.Close()
	session := app.retrieveUserSession(s, sid)
	if session == nil {
		putError(response, errorBadSid)
		return
	}

	dFiles := db.GetCol(s, filestype+".files")

	result := make([]model.FileShortMeta, 0, 10)
	meta := map[string]interface{}{}
	// TODO: rewrite
	iter := dFiles.Find(bson.M{"metadata.owner_username": session.Username}).Iter()
	for iter.Next(&meta) {
		fsm := model.FileShortMeta{
			Id:         meta["_id"].(bson.ObjectId).Hex(),
			Md5:        meta["md5"].(string),
			Size:       meta["length"].(int),
			Filename:   meta["metadata"].(map[string]interface{})["filename"].(string),
			UploadDate: meta["uploadDate"].(time.Time),
		}
		result = append(result, fsm)
	}
	response["meta"] = result
}

func (app *tramAPIApp) listUploadedData(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	app.fetchFilesMeta("data", sid, response)
	log.Println(util.Qjson(response))
}

func (app *tramAPIApp) listUploadedControl(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	app.fetchFilesMeta("control", sid, response)
	log.Println(util.Qjson(response))
}

func (app *tramAPIApp) Run() {
	app.UsernameRegexp, _ = regexp.Compile("^[_a-zA-Z][_0-9a-zA-Z]+")

	// MONGO INIT SECTION
	// TODO: show error when env not set
	mongoSocket := "tram-mongo:27017"
	log.Println("Connect to mongo at: ", mongoSocket)
	session, err := db.MongoInitConnect(mongoSocket)
	if err != nil {
		log.Fatal(err)
	}
	app.MgoSession = session

	rabbitUser := util.GetenvDefault("RABBIT_USER", "guest")
	rabbitPassword := util.GetenvDefault("RABBIT_PASSWORD", "guest")
	amqpSocket := fmt.Sprintf("amqp://%v:%v@tram-rabbit:5672", rabbitUser, rabbitPassword)
	log.Println("Connect to amqp at: ", amqpSocket)
	amqpCon, err2 := db.RabbitInitConnect(amqpSocket)
	if err2 != nil {
		log.Fatal(err2)
	}
	app.QCon = amqpCon

	// HTTP INIT SECTION
	apiBuilder := web.NewApiBuilder() // todo add config
	apiBuilder.HandleJson("/user/register", app.userRegister)
	apiBuilder.HandleJson("/user/login", app.login)
	apiBuilder.HandleJson("/user/logout", app.logout)
	apiBuilder.HandleJson("/user/info", app.getUserInfo)
	apiBuilder.HandleJson("/uploads/data/list", app.listUploadedData)
	apiBuilder.HandleJson("/uploads/data/add", app.uploadComputationData)
	apiBuilder.HandleJson("/uploads/data/remove", app.removeUploadedData)
	apiBuilder.HandleJson("/uploads/control/list", app.listUploadedControl)
	apiBuilder.HandleJson("/uploads/control/add", app.uploadControlScript)
	apiBuilder.HandleJson("/uploads/control/remove", app.removeUploadedControl)
	apiBuilder.HandleJson("/task/execute", app.enqueueExecute)
	apiBuilder.HandleJson("/task/status", app.getTaskStatus)
	apiBuilder.AddStaticDir("/js/")
	mux := apiBuilder.Build()

	log.Println("Listening on *:8080...")
	http.ListenAndServe(":8080", mux)
}

func (app *tramAPIApp) Stop() {
	app.MgoSession.Close()
	app.QCon.Close()
}

func main() {
	app := tramAPIApp{}

	defer app.Stop()
	app.Run()
}
