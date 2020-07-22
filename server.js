if (process.env.NODE_ENV != 'production') {
    require('dotenv').config()
}

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const pgp = require('pg-promise')()


const db = pgp('postgresql://local_user:user@localhost:5432/local_user')


const initializePassport = require('./passport-config')

db.any("SELECT * FROM users")
    .then(users => {
        console.log(users)
        initializePassport(
            passport,
            email => users.find(user => user.email === email),
            created_at => users.find(user => user.created_at === created_at)
        )

    }).catch(e => {
        console.error(e)
    })

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
})

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
})

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)

        db.none('INSERT INTO users(name, email, password_hash, created_at) VALUES($1, $2, $3, $4)',
            [req.body.name, req.body.email, hashedPassword, Date.now().toString()])
            .then(() => {
                res.redirect('/login')
            })
            .catch(e => {
                console.error(e)
            });
    } catch {
        res.redirect('/register')
    }
    req.body.email
})

app.delete('/logout', (req, res) => {
    req.logOut()
    res.redirect('/login')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}))

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }
    return res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/')
    }
    next()
}

app.listen(3000)