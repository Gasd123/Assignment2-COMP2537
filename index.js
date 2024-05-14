//Copied from the Demo Code
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

// initialize view engine as ejs
app.set('view engine', 'ejs');
//End of copied code

// Add cache control middleware. This prevents the browser from caching the page and returning to session required areas.
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

// Signup route
app.get('/signup', (req, res) => {
    let errorMessage = '';
    // Check if there is an error query parameter and set errorMessage accordingly
    if (req.query.error === 'invalid') {
        errorMessage = 'Invalid input. Please try again.';
    }
    res.render("signup", {error: errorMessage});
});

//From /signup to submit a new user
app.post('/submitUser', async (req,res) => {
    var email = req.body.email;
    var name = req.body.name;
    var password = req.body.password;

    // Check if any field is empty
    if (!email || !name || !password) {
        return res.redirect("/signup?error=invalid");
    }

	const schema = Joi.object(
		{
			name: Joi.string().max(50).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({email, password, name});

    //if there is an error, it leads back to signup
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/signup?error=invalid");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({email: email, password: hashedPassword, name: name});
	console.log("Inserted user");

    // Set user details in the session
    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.render("successfulUser", {name: name});
});

// Login route
app.get('/login', (req, res) => {

    let errorMessage = '';
    // Check if there is an error query parameter and set errorMessage accordingly
    if (req.query.error === 'invalid') {
        errorMessage = 'Invalid username/password combination';
    }
    res.render("login", {error: errorMessage});
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    // Check if email field is empty
    if (!email) {
        return res.redirect("/login?error=invalid");
    }

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);

    // If email is not a valid email address, redirect back to login page with an error message
    if (validationResult.error != null) {
        console.log(validationResult.error);
        return res.redirect("/login?error=invalid");
    }

    const result = await userCollection.findOne({ email: email });

    // If user not found, redirect back to login page with an error message
    if (!result) {
        console.log("User not found");
        return res.redirect("/login?error=invalid");
    }

    // If password is incorrect, redirect back to login page with an error message
    if (!(await bcrypt.compare(password, result.password))) {
        console.log("Incorrect password");
        return res.redirect("/login?error=invalid");
    }

    // Set session variables and redirect to logged in page
    req.session.authenticated = true;
    req.session.email = result.email;
    req.session.name = result.name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/loggedin');
});


app.get('/loggedin', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

    try {
        const email = req.session.email;

        // Fetch the user's name from the database based on their email
        const user = await userCollection.findOne({ email: email }, { projection: { name: 1 } });

        if (user) {
            // If user found, display the logged-in message along with the user's name
            req.session.name = user.name;


            res.render("loggedin", {name: user.name});
        } else {
            // If user not found, log out the user
            req.session.destroy();
            res.redirect('/login');
        }
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Home page route
app.get('/', (req, res) => {
    if (req.session.name) {
        // If user is logged in
        res.render("home", { user: req.session.name });
    } else {
        // If user is not logged in
        res.render("home", { user: null });
    }
});

// Members Area route
app.get('/members', (req, res) => {

    // If not logged in, redirect to the login page
    if (!req.session.name) {
        res.redirect('/login');
        return; 
    }

    res.render("members", {name: req.session.name});

});

app.

app.use(express.static(__dirname + "/public"));

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 