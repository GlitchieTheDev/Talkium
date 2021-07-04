console.clear()
console.log("ATTEMPTING TO CONNECT TO SERVER")

const express           = require("express")
const session           = require("express-session")
const hbs               = require("express-handlebars")
const mongoose          = require("mongoose")
const passport          = require("passport")
const localStrategy     = require("passport-local").Strategy
const bcrypt            = require("bcrypt")

const app               = express()

require("dotenv").config()

var username, password

mongoose.connect(process.env.DB_ConnectionString || "mongodb://localhost:27017", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})

const UserSchema        = new mongoose.Schema({
    username: {
        type            : String,
        required        : true
    },
    password: {
        type            : String,
        required        : true
    }
})

const User = mongoose.model("User", UserSchema)

// Middleware
app.engine("hbs", hbs({ extname: ".hbs" }))
app.set("view engine", "hbs")
app.use(express.static(__dirname + "/public"))
app.use(session({
    secret              : process.env.secret || "verygoodsecret",
    resave              : false,
    saveUninitialized   : true
}))
app.use(express.urlencoded({ extended: false }))
app.use(express.json());

// Passport
app.use(passport.initialize());
app.use(passport.session())

passport.serializeUser(function (user, done) {
    done(null, user.id)
})

passport.deserializeUser(function (id, done) {
    // Setup user model
    User.findById(id, function (error, user) {
        done(error, user)
    })
})

passport.use(new localStrategy( function (username, password, done) { 
    User.findOne({ username: username }, function (error, user) {
        if (error) return done(error)
        if (!user) return done(null, false, { message: "Incorrect Username." } )

        bcrypt.compare(password, user.password, function ( error, res ) {
            if ( error ) return done( error )
            if ( res === false ) { return done( null, false, { message: "Incorrect Password." } ) }

            return done( null, user )
        })
    })
}))

function isLoggedIn (req, res, next) {
    if (req.isAuthenticated()) return next()
    res.redirect("/register")
}

function isLoggedOut(req, res, next) {
    if (!req.isAuthenticated()) return next()
    res.redirect("/")
}

// Routes

app.get("/", isLoggedIn, ( req, res ) => {
    res.render( "index", { title: "Home", username: username } )
} )

app.get("/register", isLoggedOut, (req, res) => {
    res.render("register",
    {
        title       : "Register",
        error       : req.query.error
    })
})

app.get("/settings", isLoggedIn, (req, res) => {
    res.render("settings", { title: "Settings" })
})

app.get("/joinChat", isLoggedIn, (req, res) => {
    res.render("joinChat", { title: "Join Chat" })
})

app.get("/login", isLoggedOut, ( req, res ) => {
    const response = {
        title       : "Login",
        error       : req.query.error
    }

    res.render( "login", response )
} )

app.post("/login", passport.authenticate("local", {
    successRedirect : "/",
    failureRedirect : "/login?error=true"
}))

app.get( "/logout", function ( req, res ) {
    req.logout()
    res.redirect("/")
} )

app.post("/register", async ( req, res ) => {
    username        = req.body.username
    password        = req.body.password

    const exists = await User.exists({ username: username })

    if ( !exists ) {
        res.redirect("/setup")
    } else {
        res.redirect("/register?error=true")
    }
})

// Setup Our Admin User

app.get("/setup", async ( req, res ) => {
    const exists    = await User.exists({ username: username })

    if ( exists ) {
        res.redirect("/login")
        return
    }

    bcrypt.genSalt(10, function (error, salt) {
        if (error) return next(error)
        bcrypt.hash(password, salt, function ( error, hash ) {
            if (error) return next(error)
            const newAdmin = new User({
                username: username,
                password: hash
            })

            newAdmin.save()

            res.redirect("/login")
        })
    })
    console.log(`CREATED AN ACCOUNT CALLED ${username}`)
})

app.listen(5500, '0.0.0.0', ( req, res ) => {
    console.log("SUCCESSFULLY CONNECTED TO SERVER ON PORT 5500")
})
