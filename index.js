const express = require('express');
const mongoose = require('mongoose');
const app = express();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;


//you can access './' and '/persons' only if you are having login credentials and authorized access

passport.use(new localStrategy(async(username, password ,done)=>{
    try{
        console.log("received credentials",username,password);
        const user = await Person.findOne({username : username});
        if(!user) return done(null,false,{message : "User not found"});
        else console.log("user found")
        const passwordMatch =await user.comparePassword(password);
        if(passwordMatch){
            return done(null,user);
        }else{
            return done(null,false,{message : "password mismatch"});
        }
    }catch(err){
        console.log(err)
    }
}))


app.use(passport.initialize());
app.use(bodyParser.json());
mongoose.connect("mongodb://localhost:27017/praveen", { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;

db.on('error', (err) => console.error(err));
db.on('connected',()=>console.log("successs to db connection"));
db.on('disconnected', ()=>console.log("disconnected db connection"));

app.listen(7777,()=>console.log("Server started listening on port 7777"));

app.get('/',passport.authenticate('local',{session:false}),(req, res)=>{
    res.send("you are an authorized user");
})

const personSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique:true
    },
    password: {
        type: String,
        required: true
    }
});

personSchema.methods.comparePassword = async function(candidatePassword){
    try{
        const isMatch = await bcrypt.compare(candidatePassword,this.password);
        return isMatch;
    }catch(e){
        console.log(e);
    }
}
personSchema.pre('save', async function(next) {
    try {
        const person = this;
        if (!person.isModified('password')) return next();
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(person.password, salt);
        person.password = hashedPassword;
        next();
    } catch (e) {
        console.error(e)
    }
})

const Person = mongoose.model("Person", personSchema);

app.get('/persons',passport.authenticate('local',{session:false}), async (req, res) => {
    try {
        const fetchedData = await Person.find();
        res.json(fetchedData);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/create', async (req, res) => {
    try {
        const { username, password } = req.body;
        const existingPerson = await Person.findOne({ username });
        if (existingPerson) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        const newPerson = new Person({ username, password });
        const response = await newPerson.save();
        res.status(201).json(response);
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: 'Bad request. Please check your request parameters.' });
    }
});


app.post("/login",async(req,res)=>{
    try{
        const { username, password } = req.body;
        const existingPerson = await Person.findOne({ username : username, password : password });
        if(existingPerson){
            return res.json({succes : "login success"});
        }else{
            return res.json({failed : "Login failed"});
        }
    }catch(err){
        console.log(err)
    }
})
