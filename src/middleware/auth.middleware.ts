import { NextFunction, Request, Response } from "express";
import { verify } from "jsonwebtoken";
import { getManager } from "typeorm";
import { User } from "../entity/user.entity";

export const authMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const jwt = req.cookies["access_token"];

    const payload: any = verify(jwt, process.env.ACCESS_TOKEN_SECRET_KEY);

    if (!payload) {
      return res.status(401).send({ message: "Unauthenticated" });
    }

    const repository = getManager().getRepository(User);

    //Set user value in req
    const user = await repository.findOne(payload.id);

    if (!user) {
      return res.status(401).send({ message: "Unauthenticated" });
    }

    req["user"] = user;

    next();
  } catch (error) {
    return res.status(401).send({ message: "Unauthenticated" });
  }
};
