import { v2 as cloudinary } from 'cloudinary';
import { response } from 'express';
import fs from "fs"


const uploadCloudinary = async (localFilePath) => {
    try {
        if(!localFilePath) return null
        cloudinary.uploader
       .upload(localFilePath, {
        resource_type: "auto"
       })
       console.log("file is uploaded on cloudinary", response.url);
       return response;

    } catch (error) {
        fs.unlinkSync(localFilePath) 
        return null;
    }
}


    // Configuration
    cloudinary.config({ 
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
        api_key: process.env.CLOUDINARY_API_KEY, 
        api_secret: process.env.CLOUDINARY_API_SECRET
    });
