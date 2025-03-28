// require('dotenv').config({path: './env'})
import dotenv from "dotenv"
import connectDB from "./db/index.js";

import express from 'express';
const app = express();
import userRouter from "./routes/user.routes.js";

// Configure middleware, routes, etc.
app.use(express.json());
app.use("/api/v1/users",userRouter)


dotenv.config({
    path: './.env'
})



connectDB()
  .then(() => {
    app.listen(process.env.PORT || 8000, () => {
      console.log(`⚙️  Server is running at port: ${process.env.PORT || 8000}`);
    });
  })
  .catch((err) => {
    console.log("MONGO db connection failed !!! ", err);
  });



export { app };























/*
import express from "express"
const app = express()
( async () => {
    try {
        await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
        app.on("errror", (error) => {
            console.log("ERRR: ", error);
            throw error
        })

        app.listen(process.env.PORT, () => {
            console.log(`App is listening on port ${process.env.PORT}`);
        })

    } catch (error) {
        console.error("ERROR: ", error)
        throw err
    }
})()

*/