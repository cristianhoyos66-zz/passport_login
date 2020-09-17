const localStrategy = require('passport-local').Strategy;
const googleStrategy = require('passport-google-oauth2').Strategy;
const argon2 = require('argon2');

function initialize(passport, getUserByEmail, getUserById) {
    let user = {};
    const authenticateUser = async (email, password, done) => {
        user = getUserByEmail(email);
        if (user == null) {
            return done(null, false, { message: 'No user with that email' });
        }

        try {
            if (await argon2.verify(user.password, password)) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Password Incorrect' });
            }
        } catch (e) {
            return done(e);
        }
    };

    const gmailAuthenticate = function(req, accessToken, refreshToken, profile, done) {
        user = {
            id: Date.now().toString(),
            name: profile.displayName,
            email: profile.email,
            password: ''
        };
        return done(null, user);
    };

    passport.use(new localStrategy({ usernameField: 'email' }, authenticateUser));
    passport.use(
        new googleStrategy(
            {
                clientID: process.env.GMAIL_CLIENT_ID,
                clientSecret: process.env.GMAIL_CLIENT_SECRET,
                callbackURL: '/auth/google/callback',
                passReqToCallback: true
            },
            gmailAuthenticate
        )
    );

    passport.serializeUser((user, done) => {
        return done(null, user.id);
    });

    passport.deserializeUser((id, done) => {
        return done(null, user);
    });
}

module.exports = initialize;
