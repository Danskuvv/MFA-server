import CustomError from '../../classes/CustomError';
import { Request, Response, NextFunction } from 'express';
//import { TwoFA } from '../../types/2FA';
import TwoFAModel from '../models/twoFAModel';
import { authenticator } from 'otplib';
import qrcode from 'qrcode';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();
// TODO: Import necessary types and models

// TODO: Define setupTwoFA function
const setupTwoFA = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, userId } = req.body;
    // TODO: Register user to AUTH API

    // TODO: Generate a new 2FA secret
    const secret = authenticator.generateSecret();

    // TODO: Create the TOTP instance
    const otpauth = authenticator.keyuri(email, 'YourAppName', secret);

    // TODO: Store or update the 2FA data in the database
    await TwoFAModel.findOneAndUpdate(
      { email },
      { userId, email, twoFactorSecret: secret, twoFactorEnabled: true },
      { upsert: true }
    );

    // TODO: Generate a QR code and send it in the response
    const qrCode = await qrcode.toDataURL(otpauth);
    console.log('Generated QR Code URL:', qrCode); // Log the QR code URL
    res.json({ qrCodeUrl: qrCode });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// TODO: Define verifyTwoFA function
const verifyTwoFA = async (req: Request, res: Response, next: NextFunction) => {

  try {
    const {email, code} = req.body;
    // TODO: Retrieve 2FA data from the database- Works. Do not change
    const user2FA = await TwoFAModel.findOne({ email });
    if (!user2FA) {
      throw new CustomError('2FA data not found', 404);
    }

    // TODO: Validate the 2FA code - Works. Do not change
    const isValid = authenticator.verify({ token: code, secret: user2FA.twoFactorSecret });
    if (!isValid) {
      throw new CustomError('Invalid 2FA code', 401);
    }

    // TODO: If valid, get the user from AUTH API
    // Retrieve user information from the AUTH API
    const authResponse = await fetch(`${process.env.AUTH_URL}/api/v1/users/email/${email}`, {
      headers: {
        Authorization: `Bearer ${process.env.AUTH_API_KEY}`,
      },
    });
    const userData = await authResponse.json();
    if (!authResponse.ok) {
      throw new CustomError(userData.message, authResponse.status);
    }

    // TODO: Create and return a JWT token
       const token = jwt.sign({ id: userData.id, email: userData.email }, process.env.JWT_SECRET as string, { expiresIn: '1h' });

       console.log('login successful, token:', token);

    res.json({ message: 'Login successful', token });



  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {setupTwoFA, verifyTwoFA};
