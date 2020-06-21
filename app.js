//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const md5 = require("md5");
//const encrypt = require("mongoose-encryption");
// const bcrypt =require("bcrypt");
// const saltRounds=10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

app.use(express.static("public"));

app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');

app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('useNewUrlParser', true);
mongoose.set('useUnifiedTopology', true);
mongoose.connect("mongodb://localhost:27017/userDB");
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt,{secret: process.env.SECRET, encrypteFields: ["passord"]});
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home.ejs");
});
app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile"]})
);
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.get("/login", function(req, res) {
  res.render("login.ejs");
});
app.get("/register", function(req, res) {
  res.render("register.ejs");
});
app.get("/secrets", function(req, res) {
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets.ejs", {usersWithSecrets: foundUsers});
      }
    }
  });
});
app.get("/submit", function(req, res){
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});
app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret= submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        })
      }
    }
  })

})
app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});
app.post("/register", function(req, res) {

  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.direct("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  })
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //     // Store hash in your password DB.
  //     const newUser= new User({
  //       email: req.body.username,
  //       password: hash
  //     });
  //     newUser.save(function(err){
  //       if(err){
  //         console.log(err);
  //       }else{
  //         res.render("secrets.ejs")
  //       }
  //     });
  // });
});

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      })
    }
  })
  //   const username = req.body.username;
  //   const password = req.body.password;
  //
  //   User.findOne({email:username}, function(err, foundUser){
  //     if(err){
  //       console.log(err);
  //     }else{
  //       if(foundUser){
  //         {
  //           bcrypt.compare(password, foundUser.password, function(err, result) {
  //           if(result == true){
  //             res.render("secrets.ejs");
  //           }
  // });
  //
  //         }
  //       }
  //     }
  //   })

})
app.listen(3000, function() {
  console.log("Server is running...");
})
