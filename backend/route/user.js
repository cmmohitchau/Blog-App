// backend/route/user.js

const express = require("express");
const router = express.Router();
const zod = require("zod")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const JWT_SECRET = require("../config")

const { User } =
require("../db");

const validateUser = zod.object({
    username: zod.string().email(),
    firstName: zod.string(),
    lastName: zod.string(),
    password: zod.string().min(6 , "Password must be at least 6 characters long")
})

router.post("/signup", async(req, res) => {
    const body = req.body;
    const { success } = validateUser.safeParse(body);

    if (!success) {
        return res.status(400).json({
            msg: "Incorrect input"
        })
    }

    const existinguser = await User.findOne({ username: body.username });

    if (existinguser) {
        return res.status(409).json({
            msg: "user already exist"
        })
    }

 
    try {
        const saltRound = 10;

        const hash = await bcrypt.hash(body.password, saltRound);
        const hash_password = hash;
        
        const newUser = new User({
            username: body.username,
            firstName: body.firstName,
            lastName: body.lastName,
            hashed_password: hash_password
        });
        const userId = newUser._id; 
        await newUser.save();

        
        const token = jwt.sign({
            userId
        },JWT_SECRET)
        
        return res.status(201).json({
            msg: "Signup successful",
            token : token
        })
    } catch (err) {
        console.log("error during user signup: " , err);
        
        return res.status(500).json({
            msg: "Error while sign up",
        })
    }
});


const signInBody = zod.object({
    username: zod.string().email(),
    password: zod.string()
})


router.post("/signin", async(req, res) => {
    const body = req.body;
    const { success } = signInBody.safeParse(body);

    if (!success) {
        return res.status(400).json({
            msg: "Incorrect input"
        })
    }
    const existingUser = await User.findOne({username : body.username});

    if(!existingUser) {
        return res.status(404).json({
            msg  : "user not found"
        })
    }
    

    try {
        const match = await bcrypt.compare(body.password, existingUser.hashed_password);
        const userId = existingUser._id;
        
        
        if (match) {
            const token = jwt.sign({
                userId
            }, JWT_SECRET);


            return res.status(200).json({
                msg: "Login successful",
                token: token
            })
        } else {
            return res.status(401).json({ 
                msg: "Invalid credentials"
            });
        }
 
    } catch (err) {
        return res.status(500).json({
            msg: "Error logging in",
        })
    }
});

module.exports = router;