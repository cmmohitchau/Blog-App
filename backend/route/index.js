// backend/route/index.js
const express = require("express")
const userRouter = require("./user")
const adminRouter = require("./admin")
const blogRouter = require("./blog")

const router = express.Router()

router.use('/user', userRouter);
router.use('/admin', adminRouter);
router.use('/blog', blogRouter)

module.exports = router;
