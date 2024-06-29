import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import multer from 'multer'
import fs from 'fs'
const app = express();
const port = 3000;
const saltRounds = 10;
var role
env.config();

// inside multer({}), file upto only 1MB can be uploaded


var storage = multer.diskStorage({
  destination:"single",
  filename: function (req, file, cb) {
  cb(null, file.originalname)
  }
})

const upload = multer({ storage: storage }).single('file');

app.use(
  session({
    secret: "TOPSECRETWORD",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "tests",
  password: "password",
  port: 5972,
});
db.connect();

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    switch(role){
      case 'admin': res.redirect('/admin');break;
      case 'examiner': res.redirect('/examiner');break;
      case 'invigilator': res.redirect('/invigilator');break;
      default: ;
    }
  } else {
    res.redirect("/login");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const role = req.body.role;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (username, password_hash , role) VALUES ($1, $2, $3) RETURNING *",
            [username, hash, role]
          );
          const user = result.rows[0];

         
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
          
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.get('/aboutus',(req,res)=>{
  res.render('aboutus.ejs')
})

app.get('/admin',async (req,res) => {
  console.log(role)
  var logs = await db.query('SELECT * FROM logs')
  logs = logs.rows
  // try{
  // // var examiner_post = (await db.query('SELECT * from examiner_posts')).rows[0]
  // // var examiner_name = (await db.query('SELECT examiner_name from examiner where examiner_id = $1',[examiner_post.examiner_id])).rows[0]

  // // await db.query('DELETE from examiner_posts')
  // }catch(err){
  //   console.log('Bohot badi error...');
  // }
  res.render("administrator.ejs",{logs : logs});
})
app.get('/examiner',(req,res) => {
    console.log(role)
    res.render("secrets.ejs",{role:role});
})
app.get('/invigilator',async (req,res) => {
  if(req.isAuthenticated()){
    
    var file = await db.query('SELECT questionpaper FROM invigilator_access WHERE acc_id = $1',[1])
    // var file = new File(file)
    // console.log(typeof(file))
    // console.log(file);

    res.render('invigilator.ejs')
  }
})

app.post('/admin',(req,res)=>{

})

app.post('/uploadfile', upload ,async (req, res) => {
  if(req.file){
    const  startDate  = req.body.startDate;
    const startTime= req.body.startTime;
    const  validity  = req.body.validity;
    const startDateTime = new Date(`${startDate}T${startTime}`);
    const endDateTime = new Date(startDateTime.getTime() + validity * 60000);
    await db.query('INSERT INTO invigilator_access(examiner_id, start_time, end_time, questionpaper) values ($1,$2,$3,$4)',[1,startDateTime,endDateTime,`pg_read_binary_file(/single/'${req.file.originalname}')`])
  }
  res.redirect('/admin')
})

app.post('/invigilator',(req,res)=>{
  
})

passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE username = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password_hash;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              role = user.role
              return cb(null, user);

            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
