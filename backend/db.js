// backend/db.js

const mongoose = require("mongoose");

async function connectDb() {
    try {
        await mongoose.connect("mongodb://localhost:27017/Blog-app");
        console.log("connected to db");
    } catch (err) {
        console.log("Database connection error" , err)
    }
}

connectDb();

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
    },
    firstName: {
        type: String,
        required: true,
    },
    lastName: {
        type: String,
        required: true,
    },
    hashed_password: {
        type: String,
        required: true
    },
    blogs : [{
        type : mongoose.Schema.Types.ObjectId,
        ref : 'Blog'
    }]
});

const adminSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
    },
    firstName: {
        type: String,
        required: true,
    },
    lastName: {
        type: String,
        required: true,
    },
    hashed_password: {
        type: String,
        required: true
    },
    
});

const BlogSchema = new mongoose.Schema({
    title : {
        type : String ,
        required : true,
    },
    content : {
        type : String,
        required : true
    },
    date : {
        type : Date,
        default :  Date.now
    },
    authorId : {
        type : mongoose.Schema.Types.ObjectId,
        ref : 'User',
        require : true
    }
})
const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin' , adminSchema);
const Blog = mongoose.model('Blog' , BlogSchema)
module.exports = {
    User,
    Admin,
    Blog
}