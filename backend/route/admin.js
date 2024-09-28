// backend/route/admin.js

const express = require("express")
const zod = require("zod");
const bcrypt = require("bcrypt")
const { Admin } = require('../db')
const JWT_SECRET = require("../config")
const jwt = require('jsonwebtoken')

const router = express.Router();

const AdminBody = zod.object({
    username : zod.string().email(),
    password : zod.string()
})

router.post("/signin" , async (req,res) => {
    const body = req.body;
    const {success} = AdminBody.safeParse(body);

    if(!success) {
        return res.status(400).json({
            msg : "Incorrect input",
        })
    }

    const existingUser = await Admin.findOne({username : body.username});

    if(!existingUser) {
        return res.status(401).json({
            msg : "Admin does not exist"
        })
    }

    
    try {
        const match = await bcrypt.compare(body.password, existingUser.hashed_password);

        if (match) {
            const token = jwt.sign({
                userId : existingUser._id
            }, JWT_SECRET);
            res.status(200).json({
                msg: "Login successful",
                username: username,
                token: token
            })

        } else {
            return res.status(401).json({ 
                msg: "Invalid credentials"
            });
        }
    } catch (err) {
        console.log('error during admin signin');
        
        return res.status(500).json({
            msg: "Error logging in",
        })
    }

})

module.exports = router;