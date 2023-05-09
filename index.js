
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3200;

const app = express();

const Joi = require("joi");


const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = "cluster0.vsnudks.mongodb.net";
const mongodb_user = "user1";
const mongodb_password = "Strongholdminer12";
const mongodb_database = "bobsData";
const mongodb_session_secret = "f03db5da-0fae-486f-b984-9cb21d39d3d4";

const node_session_secret = "39c3e734-7a37-43ce-9609-7f9aacac9369";
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

app.set('view engine', 'ejs');

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/session`,
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

app.get('/', (req,res) => {
    var sessionState = req.session.authenticated;
    var username = req.session.username;

    res.render("home", {isLoggedIn: sessionState, userName: username});
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    res.render("about");
});

app.get('/users', (req,res) => {

    res.render("users", {users: [{username: "me", email: "me@b.ca"}, {username: "you", email: "you@b.ca"}]});

});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/createUser', (req,res) => {
    res.render("createUser");
});


app.get('/login', (req,res) => {
    res.render("login");
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
			email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       var error = validationResult.error.details[0].message;
       res.render("signupError", {theError: error});
	   return;
   }
   

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, password: hashedPassword, user_type: 'user'});
	console.log("Inserted user");

    
    res.redirect('/members');
});

app.get('/members', (req,res) => {
    var username = req.session.username;
    const randomNumber = Math.floor(Math.random() * 3);
    if (req.session.authenticated) {

        res.render("members", {user: username, randCat: randomNumber});

    }
    else {
        res.redirect('/login');
    }
    
    
});

app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedIn');
		return;
	}
	else {
		console.log("incorrect password");
        res.render("loginError");
		return;
	}
});


app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.redirect('/members');
    
});

app.get('/admin', async (req,res) => {
    var username = req.session.username;
    var user = await userCollection.findOne({ username: username });
    var user_type = user.user_type;
    if (req.session.authenticated) {
        const users = await userCollection.find().toArray();
        res.render("admin", {userType: user_type, users: users})
    }
    else {
        res.redirect('/login');
    }
    
});

app.get('/promoteUser', async (req,res) => {
    var username = req.query.username;
    await userCollection.updateOne({username: username}, {$set: {user_type: 'admin'}});
    res.redirect("/admin");
});
app.get('/demoteUser', async (req,res) => {
    var username = req.query.username;
    await userCollection.updateOne({username: username}, {$set: {user_type: 'user'}});
    res.redirect("/admin");
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    var sessionState = false;
    var username = "";

    res.render("home", {isLoggedIn: sessionState, userName: username});
});


app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: "+cat);
    }
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 