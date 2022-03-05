import { Request, Response } from "express";
import { Reset } from "../entity/reset.entity";
import { getManager } from "typeorm";
import { User } from "../entity/user.entity";

export const Forgot = async (req: Request, res: Response) => {
  const { email } = req.body;

  const token = Math.random().toString(20).substring(2, 12);

  const repository = getManager().getRepository(Reset);

  const reset = await repository.save({
    email,
    token,
  });

  //   Send mail with nodemailer
  // Send url to reset password

  // url = `http//localhost:3000/reset/${token}`
};

export const ResetPassword = async (req: Request, res: Response) => {
  const { token, password, confirm_password } = req.body;

  const repository = getManager().getRepository(Reset);

  const resetPassword = await repository.findOne({ token });
  if (!resetPassword) {
    return res.status(400).send({ message: "Invalid link" });
  }

  const userRepository = getManager().getRepository(User);

  const user = await userRepository.findOne({ email: resetPassword.email });

  if (!user) {
    return res.status(404).send({ message: "User not found" });
  }

  //   await userRepository.update(user.id, password: encrypted password by importing bcrypt)
};
