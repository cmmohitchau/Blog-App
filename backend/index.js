// backend/index.js
const express = require("express")
const cors = require("cors")
require("./db.js")
const app = express()


app.use(cors())
app.use(express.json())
const mainRouter = require("./route/index.js")


app.use("/api/v1" , mainRouter);

const port = 3000;

app.listen(port , () => {
    console.log("app is listening at port " , port);
})