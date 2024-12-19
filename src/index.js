// import mongoose from "mongoose"
// import { DB_NAME } from "./constants.js"

import { app } from "./app.js"
import dotenv from "dotenv"
import connectDB from "./db/index.js"
dotenv.config({
    path: './.env'
})

connectDB()
    .then(() => {
        app.on("Error", (error) => {
            console.log("ERROR :", error)
            throw error;
        })
        app.listen(process.env.PORT || 8000, () => {
            console.log(`App is listening on port ${process.env.PORT}`)
        })
    })
    .catch((err) => {
        console.log("MONGODB connection Failed !!!!", err)
    })



/*
(async () => {
    try {
        await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
        
        app.on("Error", () => {
            console.log("ERR : ", error);
            throw error;
        })

        app.listen(process.env.PORT, () => {
            console.log(`App is listeninig on port ${process.env.PORT}`)
        })
    } catch (error) {
        console.error("Mongodb connection FAILED", error);
        throw error
    }
})()

*/