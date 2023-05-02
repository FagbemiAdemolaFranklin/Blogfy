require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose =require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const https = require("https");
const request = require("request");
const { error } = require("console");
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.set('trust proxy', 1);
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
mongoose.set("strictQuery", false);
main(). catch(err => console.log(err));
async function main(){
  try{
    await mongoose.connect(process.env.MONGO_URI);
  }catch(error){
    console.log(error);
  }
 
  
  const userSchema = new mongoose.Schema ({
    email:String,
    password:String,
    contents:[Object]
  });

  userSchema.plugin(passportLocalMongoose);
  userSchema.plugin(findOrCreate);

  const User = new mongoose.model("User", userSchema);

  passport.use(User.createStrategy());

    passport.serializeUser(function(user, done){
        done(null, user);
    })
    passport.deserializeUser(function(user, done){
        done(null, user);
    });

    passport.use(new GoogleStrategy({
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "https://proud-gray-bonnet.cyclic.app/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb) {
      User.findOrCreate({email:profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  ));

    app.get("/", async function(req, res){
        try{
            var options = {
                method:"GET",
                headers:{
                    "X-Api-Key": process.env.KEY
                }
            }
        
            await fetch("https://newsapi.org/v2/top-headlines?country=us&category=entertainment&health", options)
            .then(function(response){
                response.json().then(function(data){
                    res.render("home", {latestArticles:data.articles});
                })
            }).catch(err => console.log(err));
        }catch{
            console.log(err);
            res.redirect("/");
        }
    });

    app.get("/auth/google",
        passport.authenticate('google', { scope: ["profile"] })
    );

    app.get("/auth/google/secrets",
        passport.authenticate('google', { failureRedirect: "/login" }),
        function(req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect("/secrets");
    });

    app.get("/login", function(req, res){
        try{
            res.render("login");
        }catch{
            console.log(error);
            res.redirect("/login")
        }
        
    });

    app.get("/register", function(req, res){
        try{
            res.render("register");
        }catch{
            console.log(error);
            res.redirect("/register");
        }
       
    });

    app.get("/secrets", async function(req, res){
        try{
            const user = req.session.passport.user.username
            console.log(user);
            await User.find({username:user}).then(function(foundUsers){ 
                var blogs = foundUsers[0].contents;
                res.render("secrets", {usersWithSecrets:blogs});
            }).catch(err => console.log(err));
        }catch{
            console,log(error);
            res.redirect("/secrets");
        }
    });

    app.get("/submit", async function(req, res){
        try{
            if (req.isAuthenticated()){
                res.render("submit");
                } else {
                res.redirect("/login");
                }
        }catch{
            console.log(error);
            res.redirect("/submit");
        }
        
    });

    app.post("/submit", async function(req, res){
        try{
            const submittedTitle = req.body.title;
            const submittedContent = req.body.content;

            var blog = {
                title:submittedTitle,
                content:submittedContent
            }
            await User.findOneAndUpdate({username:req.session.passport.user.username}, {$push:{"contents":blog}}).then(function(done){
                res.redirect("/secrets");
            }).catch(err => console.log(err));
        }catch{
            console.log(error);
            res.redirect("/submit");
        }
        
    }) 

    app.get("/logout", async function(req, res){
        
        try{
            req.logout(function(err){
                if(err){
                    console.log(err);
                }else{
                    res.redirect("/");
                }
            });
        }catch{
            console.log(error);
            

        }  
    });

    app.post("/register", async function(req, res){
        try {
            await User.register({username: req.body.username}, req.body.password, function(err){
                if (err) {
                    const body = "Username is already taken"
                    res.writeHead(401, {
                        'Content-Length':Buffer.byteLength(body),
                        'Content-Type':'text/plain'
                    })
                    res.end(body);
                    
                }else{
                    res.redirect("/logIn");
                }
                });  
        }catch {
            console.log(error);
            res.redirect("/register");
        }
       
    });

    app.post("/login", function(req, res){
        try{
            const user = new User({
                username: req.body.username,
                password: req.body.password
                });
        
                req.login(user, function(err){
                if (err) {
                   console.log(err);
                    
                } else {
                    passport.authenticate("local", {failureRedirect:"/login", failureFlash:true})(req, res, function(err){
                        if(err){
                            const body = "username or password is incorrect"
                            response
                            .writeHead(401, {
                                'Content-Length': Buffer.byteLength(body),
                                'Content-Type': 'text/plain'
                            })
                            .end(body);
                        }else{
                            res.redirect("/secrets");
                        }
                    
                    });
                }
                });
        }catch{
            console.log(error);
            res.redirect("/login");
        }
        

    });

    app.listen(3000, function() {
        console.log("Server started on port 3000.");
    });

}