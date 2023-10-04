const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const connection = require("./database");
const error = require("mongoose/lib/error");
const { validPassword } = require("../lib/passwordUtils");
const User = connection.models.User;

//! In case we have some custom name for username and password to look for in the db
const customFields = {
	usernameFields: "username",
	passwordFeilds: "password",
};

const verifyCallback = (username, password, done) => {
	User.findOne({ username: username })
		.then((user) => {
			if (!user) {
				return done(null, false); //HELP No user found
			}
			//! hash the entered-password and check it with stored password
			const isValid = validPassword(password, user.hash, user.salt);
			if (isValid) {
				return done(null, user); //HELP MATCH!
			} else {
				return done(null, false);
			}
		})
		.catch((error) => {
			done(error);
		});
};

const Strategy = new LocalStrategy(verifyCallback, customFields);

passport.use(Strategy);

passport.serializeUser((user, done) => {
	done(null, user.id);
});

passport.deserializeUser((userId, done) => {
	User.findById(userId)
		.then((user) => {
			done(null, user);
		})
		.catch((error) => {
			done(error);
		});
});
