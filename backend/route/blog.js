// backend/route/blog.js
const express = require('express')
const router = express.Router()
const mongoose = require('mongoose')
const {Blog } = require('../db')
const { authMiddleware } = require('../middleware')
router.use(authMiddleware);
console.log('authMiddleware:', authMiddleware);


router.post('/' ,async (req , res) => {
    try {
        const {content , title} =  req.body;

        if(!title || !content) {
            return res.status(400).json({ message: 'Title and content are required' })
        }
        const userId = req.userId
        

        const newBlog =await Blog.create({
            title : title,
            content : content,
            authorId : userId
        });

        return res.status(201).json({
            id : newBlog._id,
            msg : "blog created successfully"
        })
    } catch (e) {
        console.log("error creating blog:" , e);
        return res.status(500).json({msg : "server error for creating blog"});
    
    }
})
router.put('/:id', async (req, res) => {
    try {
      const { title, content } = req.body;
      const userId = req.userId;
      const blogId = req.params.id;
  
      const updateFields = {};
      if (title) updateFields.title = title;
      if (content) updateFields.content = content;
  
      const response = await Blog.findOneAndUpdate(
        { _id: blogId, authorId: userId },  
        { $set: updateFields },
        { new: true }  
      );
  
      if (!response) {
        return res.status(404).json({ msg: 'Blog not found or user not authorized' });
      }
  
      return res.status(200).json({ msg: 'Update successful', blog: response });
    } catch (e) {
      return res.status(500).json({ msg: 'Server error for updating blog', error: e.message });
    }
  });

router.get('/bulk' , async (req , res) => {
    
    try {
        
    const blogs = await Blog.find({}).populate('authorId');
    
    return res.json({
        blogs : blogs
    })
    } catch (e) {
        console.log("Error fetching blogs:" , e);
        
        return res.json({
            error : "Error while fetching blogs"
        })
    }


})


router.get('/:id' , async(req,res) => {
    try {
        const id = req.params.id;
        
        const blog = await Blog.findById(id).populate('authorId');
      
        
        return res.status(200).json({
            blog : blog
        });
    } catch(e) {
        return res.status(500).json({
            msg : "server error for getting blog"
        })
    }
  })

router.delete('/:id' , async(req,res) => {
    

    try {
        const id = req.params.id;
        const response =await Blog.findByIdAndDelete(id);
        res.status(200).json({
            msg : "deleted successful"
        })

    } catch(e) {
        console.log("Error while deleting");
        res.status(500).json({
            msg : "Error while deleting blog"
        })
        
    }
})
  

module.exports = router