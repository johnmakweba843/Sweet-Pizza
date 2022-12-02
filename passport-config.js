const localStrategy = require("passport-local").Strategy 
const bcrypt = require("bcrypt") 

function initialize(passport , getUserByEmail , getUserById){ 
    const authenticateUser = async(email , password , done) => { 
        const user = getUserByEmail(email) 
        if(user == null){ 
            return done(null , false , {message:"no user is found in this email"})
        } 
        try {
            if(await bcrypt.compare(password , user.password)){ 
                return done(null , user)
            } 
            else{ 
                return done(null , false , {message:"incorrect password"})
            }
        } catch (e) {
            console.log(e) 
            return done(e)
        }
    } 
    passport.use(new localStrategy({usernameField:'email'} , authenticateUser)) 
    passport.serializeUser((user , done) => done(null , user.id)) 
    passport.deserializeUser((id , done) => { 
        return done(null , getUserById(id))
    })    
} 

module.exports = initialize