import { Request, Response } from 'express';
import { hash, compare } from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';
import { MongoClient, ObjectId } from 'mongodb';

const path = require('path')
const express = require('express');

const mongoDbConnectionString = 'mongodb://127.0.0.1:27017'
const mongoClient = new MongoClient(mongoDbConnectionString);
const databaseName ='utopia-login'
const ACCESS_TOKEN_SECRET = 'your-access-token-secret';
const REFRESH_TOKEN_SECRET = 'your-refresh-token-secret';
const ACCESS_TOKEN_EXPIRY = '120s';
const app = express();

app.use(express.json());
app.use('/',express.static(path.join(__dirname,'../static')))
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});

//sign-up user
app.post('/api/sign-up', async(req: Request, res: Response)=>{
    try{
        const { email, password } = req.body; 
    if(!email|| typeof email!=='string' ){
        return res.json({status:'error', error:'Invalid username'})
    }
    if(!password || typeof password!=='string' ){
        return res.json({status:'error', error:'Invalid password '})
    }
    if(password.length <8){
        return res.json({status:'error', error:'password should contain atleast 8 characters.'})
    }

    // Check if email already exists
    const existingUser = await mongoClient
      .db(databaseName)
      .collection('users')
      .findOne({ email });

    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    const hashedPassword = await hash(password, 10);

    // Create new user
    const newUser: any= {
      email:email,
      password: hashedPassword,
    };

    // Save user to the database
    const result = await mongoClient
      .db(databaseName)
      .collection('users')
      .insertOne(newUser);

      console.log('user added to mongodb',result)
      res.json({status:'ok'})
    }catch(error){
        console.log(error)
        return res.status(500).json({ message: 'Internal server error' });
    }
    
})

//login user
app.post('/api/login',async(req: Request, res: Response)=>{
    try {
        const { email, password } = req.body;
    
        // Find user by email
        const savedUser: any = await mongoClient
          .db(databaseName)
          .collection('users')
          .findOne({ email });
    
        if (!savedUser) {
          return res.status(401).json({ message: 'Invalid email or password' });
        }
    
        // Check if password is correct
        const passwordMatch = await compare(password, savedUser.password);
    
        if (!passwordMatch) {
          return res.status(401).json({ message: 'Invalid email or password' });
        }
        //Generate access token
        const accessToken = sign({ userId: savedUser._id }, ACCESS_TOKEN_SECRET, {
          expiresIn: ACCESS_TOKEN_EXPIRY,
        });
         // Generate refresh token
        const refreshToken = sign({ userId: savedUser._id }, REFRESH_TOKEN_SECRET);
        
        // Update refresh token in the user's record
        await mongoClient
        .db(databaseName)
        .collection('users')
        .updateOne({ _id: savedUser._id }, { $set: { refreshToken } });
    
        // Return access token and refresh token
        console.log('successful login')
        return res.json({ accessToken, refreshToken ,status:'ok'});

      } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
      }
})

//delete user
app.post('/api/delete', async(req: Request, res: Response)=>{
    try{
        const {accessToken} = req.body
        const parsedAccessToken : any= verify(accessToken, ACCESS_TOKEN_SECRET);
        const userId= parsedAccessToken.userId
        const deleteUser = await mongoClient
        .db(databaseName)
        .collection('users')
        .deleteOne({ _id: new ObjectId(userId)})
        
        return res.json({parsedAccessToken, status:'ok'})
    }catch(error){
        console.log(error)
        return res.status(500).json({ message: 'Internal server error' });
    }
})

//refresh token
app.post('/api/refreshtoken',async (req: Request, res: Response)=>{
    try{
        const {refreshToken} = req.body

        // Verify the refresh token
        const parsedRefreshToken: any = verify(refreshToken,REFRESH_TOKEN_SECRET)
        const userId= parsedRefreshToken.userId

        // Check if the user exists
        const user: any= await mongoClient
        .db(databaseName)
        .collection('users')
        .findOne({_id: new ObjectId(userId) })

        if(!user){
            return res.status(404).json({ message: 'User not found' });
        }
        // Generate new access token
        const accessToken = sign({ userId: user._id }, ACCESS_TOKEN_SECRET, {
        expiresIn: ACCESS_TOKEN_EXPIRY,
      });
      return res.json({ accessToken });
    }catch(error){
        console.log(error)
        return res.status(500).json({ message: 'Internal server error' });
    }
})

//test api, to check token verification is working properly or not!
app.post('/api/test', async (req: Request, res: Response)=>{
    try{
        if('accessToken' in req.body){
            const {accessToken} = req.body
            const parsedAccessToken : any= verify(accessToken, ACCESS_TOKEN_SECRET); 
            if(parsedAccessToken.userId){
              return res.json({message:'User successfully validated!'})  
            }
            else{
                return res.json({ message: 'Invalid API call' });
            }
        }
    }catch(error){
        console.log(error)
        return res.json({ message: 'Invalid API call' });
    }
})