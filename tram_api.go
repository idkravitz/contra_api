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
	"github.com/kravitz/tram-api/tram-commons/db"
	"github.com/kravitz/tram-api/tram-commons/model"
	"github.com/kravitz/tram-api/tram-commons/util"
	"github.com/kravitz/tram-api/tram-commons/web"

	"golang.org/x/crypto/bcrypt"

	"github.com/streadway/amqp"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const SALT_SIZE int = 8

type TramApiApp struct {
	QCon           *amqp.Connection
	MgoSession     *mgo.Session
	UsernameRegexp *regexp.Regexp
}

const (
	ERROR_USERNAME_TOO_SHORT       = "ERROR_USERNAME_TOO_SHORT"
	ERROR_USERNAME_BAD_CHARACTERS  = "ERROR_USERNAME_BAD_CHARACTERS"
	ERROR_PASSWORD_TOO_SHORT       = "ERROR_PASSWORD_TOO_SHORT"
	ERROR_USER_EXISTS              = "ERROR_USER_EXISTS"
	ERROR_BAD_PASSWORD_OR_USERNAME = "ERROR_BAD_PASSWORD_OR_USERNAME"
	ERROR_BAD_SID                  = "ERROR_BAD_SID"
	ERROR_FILE_NOT_FOUND           = "ERROR_FILE_NOT_FOUND"
	ERROR_TASK_NOT_FOUND           = "ERROR_TASK_NOT_FOUND"
)

// TODO 1: Storage location

func (app *TramApiApp) upload_computation_data(response bson.M, req *http.Request) {
	sid := req.FormValue("sid")
	s := app.MgoSession.Copy()
	defer s.Close()
	session := &model.Session{}
	err := db.GetCol(s, "sessions").Find(bson.M{"sid": sid}).One(session)
	if err != nil {
		log.Fatal(err) // stub
	}
	fid := app.upload_file(req, "file", "data", session.Username)

	response["status"] = "ok"
	response["id"] = fid
}

func (app *TramApiApp) upload_control_script(response bson.M, req *http.Request) {
	sid := req.FormValue("sid")
	s := app.MgoSession.Copy()
	defer s.Close()
	session := &model.Session{}
	err := db.GetCol(s, "sessions").Find(bson.M{"sid": sid}).One(session)
	if err != nil {
		log.Fatal(err) // stub
	}
	fid := app.upload_file(req, "file", "control", session.Username)

	response["status"] = "ok"
	response["id"] = fid
}

func (app *TramApiApp) upload_file(req *http.Request, formFile string, collection string, owner string) interface{} {
	file, header, err := req.FormFile(formFile)

	if err != nil {
		log.Println(err)
		return nil
	}

	defer file.Close()

	s := app.MgoSession.Copy()
	defer s.Close()
	fs := s.DB("tram").GridFS(collection)
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

func (app *TramApiApp) username_validator(username string) string {
	if len(username) < 4 {
		return ERROR_USERNAME_TOO_SHORT
	}
	if !app.UsernameRegexp.MatchString(username) {
		return ERROR_USERNAME_BAD_CHARACTERS
	}
	return ""
}

func getGridFS(s *mgo.Session, fsName string) *mgo.GridFS {
	return s.DB("tram").GridFS(fsName)
}

func password_validator(password string) string {
	if len(password) < 6 {
		return ERROR_PASSWORD_TOO_SHORT
	}
	return ""
}

func getSid() string {
	bytes := make([]byte, 16, 16)
	io.ReadFull(rand.Reader, bytes)
	sid, _ := bcrypt.GenerateFromPassword(bytes, bcrypt.DefaultCost)
	return string(sid)
}

func (app *TramApiApp) getUserSession(username string) *model.Session {
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

func put_error(response bson.M, err string) {
	response["status"] = "error"
	response["error"] = err
}

func (app *TramApiApp) user_register(response bson.M, req *http.Request) {
	username := req.FormValue("username")
	password := req.FormValue("password")
	email := req.FormValue("email")

	response["status"] = "ok"

	err := app.username_validator(username)
	if err != "" {
		put_error(response, err)
		return
	}
	err = password_validator(password)
	if err != "" {
		put_error(response, err)
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
	mgo_err := c.Insert(user)
	if mgo_err != nil {
		if mgo.IsDup(mgo_err) {
			put_error(response, ERROR_USER_EXISTS)
			return
		}
		log.Fatal(mgo_err)
	}

	user_session := app.getUserSession(username)
	response["sid"] = user_session.Sid

	log.Println(fmt.Sprintf("Register user: %v", util.Qjson(user)))
	log.Println(fmt.Sprintf("His session is: %v", util.Qjson(user_session)))
}

func (app *TramApiApp) retrieveUserSession(s *mgo.Session, sid string) (session *model.Session) {
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

func (app *TramApiApp) get_user_info(response bson.M, req *http.Request) {
	sid := req.FormValue("sid")
	s := app.MgoSession.Copy()
	defer s.Close()

	session := app.retrieveUserSession(s, sid)
	if session == nil {
		put_error(response, ERROR_BAD_SID)
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

func (app *TramApiApp) logout(response bson.M, req *http.Request) {
	sid := req.FormValue("sid")

	s := app.MgoSession.Copy()
	defer s.Close()

	s.DB("tram").C("sessions").Remove(bson.M{"sid": sid})
	response["status"] = "ok"
}

func (app *TramApiApp) login(response bson.M, req *http.Request) {
	username := req.FormValue("username")
	password := req.FormValue("password")
	response["status"] = "ok"

	s := app.MgoSession.Copy()
	defer s.Close()

	user := &model.User{}
	err := db.GetCol(s, "users").Find(bson.M{"username": username}).One(user)
	if err != nil || bcrypt.CompareHashAndPassword(user.Password, []byte(password)) != nil {
		put_error(response, ERROR_BAD_PASSWORD_OR_USERNAME)
		return
	}

	user_session := app.getUserSession(username)
	response["sid"] = user_session.Sid
	log.Println(fmt.Sprintf("User login: %v", user.Username))
}

func (app *TramApiApp) removeUploadedData(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	dfid := r.FormValue("data_file_id")

	s := app.MgoSession.Copy()
	defer s.Close()

	session := app.retrieveUserSession(s, sid)
	if session == nil {
		put_error(response, ERROR_BAD_SID)
		return
	}

	meta := getFileMeta(s, "data", dfid)
	if meta == nil || meta.Owner_Username != session.Username {
		put_error(response, ERROR_FILE_NOT_FOUND)
		return
	}

	getGridFS(s, "data").RemoveId(bson.ObjectIdHex(dfid))
	response["status"] = "ok"
}

func (app *TramApiApp) removeUploadedControl(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	cfid := r.FormValue("control_file_id")

	s := app.MgoSession.Copy()
	defer s.Close()

	session := app.retrieveUserSession(s, sid)
	if session == nil {
		put_error(response, ERROR_BAD_SID)
		return
	}

	meta := getFileMeta(s, "control", cfid)
	if meta == nil || meta.Owner_Username != session.Username {
		put_error(response, ERROR_FILE_NOT_FOUND)
		return
	}

	getGridFS(s, "control").RemoveId(bson.ObjectIdHex(cfid))
	response["status"] = "ok"
}

type FileMetaTemp struct {
	Metadata *model.FileDescription
}

func getFileMeta(s *mgo.Session, fsName string, fileId string) *model.FileDescription {
	fs := getGridFS(s, fsName)
	result := FileMetaTemp{}
	err := fs.Find(bson.M{"_id": bson.ObjectIdHex(fileId)}).One(&result)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil
		}
		log.Fatal(err)
	}
	return result.Metadata
	// json.Unmarshal()
}

func (app *TramApiApp) enqueue_execute(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	dfid := r.FormValue("data_file_id")
	cfid := r.FormValue("control_file_id")

	s := app.MgoSession.Copy()
	defer s.Close()
	session := app.retrieveUserSession(s, sid)
	if session == nil {
		put_error(response, ERROR_BAD_SID)
		return
	}

	dfd := getFileMeta(s, "data", dfid)
	if dfd == nil {
		put_error(response, ERROR_FILE_NOT_FOUND)
		return
	}
	cfd := getFileMeta(s, "control", cfid)
	if cfd == nil {
		put_error(response, ERROR_FILE_NOT_FOUND)
	}

	if dfd.Owner_Username != session.Username || cfd.Owner_Username != session.Username {
		put_error(response, ERROR_FILE_NOT_FOUND)
		return
	}

	ch, err_ch := app.QCon.Channel()
	if err_ch != nil {
		log.Fatal(err_ch)
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
	bMsg, err_m := bson.Marshal(&msg)
	if err_m != nil {
		log.Fatal(err_m)
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

func (app *TramApiApp) getTaskStatus(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	task_id := r.FormValue("task_id")
	s := app.MgoSession.Copy()
	defer s.Close()
	session := app.retrieveUserSession(s, sid)
	if session == nil {
		put_error(response, ERROR_BAD_SID)
		return
	}

	task := model.Task{}
	err := db.GetCol(s, "tasks").Find(bson.M{"_id": bson.ObjectIdHex(task_id)}).One(&task)
	if err != nil {
		log.Fatal(err)
	}
	if task.Owner != session.Username {
		put_error(response, ERROR_TASK_NOT_FOUND)
		return
	}
	response["task"] = task
}

func (app *TramApiApp) fetchFilesMeta(filestype string, sid string, response bson.M) {
	s := app.MgoSession.Copy()
	defer s.Close()
	session := app.retrieveUserSession(s, sid)
	if session == nil {
		put_error(response, ERROR_BAD_SID)
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

func (app *TramApiApp) listUploadedData(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	app.fetchFilesMeta("data", sid, response)
	log.Println(util.Qjson(response))
}

func (app *TramApiApp) listUploadedControl(response bson.M, r *http.Request) {
	sid := r.FormValue("sid")
	app.fetchFilesMeta("control", sid, response)
	log.Println(util.Qjson(response))
}

func (app *TramApiApp) Run() {
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
	apiBuilder.HandleJson("/user/register", app.user_register)
	apiBuilder.HandleJson("/user/login", app.login)
	apiBuilder.HandleJson("/user/logout", app.logout)
	apiBuilder.HandleJson("/user/info", app.get_user_info)
	apiBuilder.HandleJson("/uploads/data/list", app.listUploadedData)
	apiBuilder.HandleJson("/uploads/data/add", app.upload_computation_data)
	apiBuilder.HandleJson("/uploads/data/remove", app.removeUploadedData)
	apiBuilder.HandleJson("/uploads/control/list", app.listUploadedControl)
	apiBuilder.HandleJson("/uploads/control/add", app.upload_control_script)
	apiBuilder.HandleJson("/uploads/control/remove", app.removeUploadedControl)
	apiBuilder.HandleJson("/task/execute", app.enqueue_execute)
	apiBuilder.HandleJson("/task/status", app.getTaskStatus)
	apiBuilder.AddStaticDir("/js/")
	mux := apiBuilder.Build()

	log.Println("Listening on *:8080...")
	http.ListenAndServe(":8080", mux)
}

func (app *TramApiApp) Stop() {
	app.MgoSession.Close()
	app.QCon.Close()
}

func main() {
	app := TramApiApp{}

	defer app.Stop()
	app.Run()
}
