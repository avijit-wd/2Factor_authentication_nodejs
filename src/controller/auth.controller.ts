import { Request, Response } from "express";
import { getManager } from "typeorm";
import { RegisterValidation } from "../validation/register.validation";
import { User } from "../entity/user.entity";
import bcrypt from "bcryptjs";
import { sign, verify } from "jsonwebtoken";
import speakeasy from "speakeasy";

export const register = async (req: Request, res: Response) => {
  const body = req.body;

  const { error } = RegisterValidation.validate(body);

  if (error) {
    return res.status(400).send(error.details);
  }

  if (body.password !== body.confirm_password) {
    return res.status(400).send({
      message: "Password do not match",
    });
  }

  const repository = getManager().getRepository(User);

  const { password, tfa_secret, ...user } = await repository.save({
    first_name: body.first_name,
    last_name: body.last_name,
    email: body.email,
    password: await bcrypt.hash(body.password, 10),
  });

  return res.send(user);
};

// export const login = async (req: Request, res: Response) => {
//   const repository = getManager().getRepository(User);

//   const user = await repository.findOne({ email: req.body.email });

//   if (!user) {
//     return res.status(404).send({ message: "Invalid credentials" });
//   }

//   if (!(await bcrypt.compare(req.body.password, user.password))) {
//     return res.status(400).send({ message: "Invalid credentials!" });
//   }

//   // Access Token
//   const accessToken = sign(
//     { id: user.id },
//     process.env.ACCESS_TOKEN_SECRET_KEY,
//     {
//       expiresIn: "30s",
//     }
//   );

//   // Refresh Token
//   const refreshToken = sign(
//     { id: user.id },
//     process.env.REFRESH_TOKEN_SECRET_KEY,
//     {
//       expiresIn: "1w",
//     }
//   );

//   res.cookie("access_token", accessToken, {
//     httpOnly: true, //Only accessible on backend
//     maxAge: 24 * 60 * 60 * 1000, //1 day
//   });

//   res.cookie("refresh_token", refreshToken, {
//     httpOnly: true,
//     maxAge: 7 * 24 * 60 * 60 * 1000, //1 day
//   });

//   res.send({ message: "success" });
// };

// Splitted Login for 2F authentication
export const login = async (req: Request, res: Response) => {
  const repository = getManager().getRepository(User);

  const user = await repository.findOne({ email: req.body.email });

  if (!user) {
    return res.status(404).send({ message: "Invalid credentials" });
  }

  if (!(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(400).send({ message: "Invalid credentials!" });
  }

  if (user.tfa_secret) {
    return res.send({ id: user.id });
  }

  const secret = speakeasy.generateSecret({
    name: "My App",
  });

  res.send({
    id: user.id,
    secret: secret.ascii,
    otpauth_url: secret.otpauth_url,
  });
};

export const TwoFactor = async (req: Request, res: Response) => {
  try {
    const id = req.body.id;
    const repository = getManager().getRepository(User);

    const user = await repository.findOne(id);

    if (!user) {
      return res.status(400).send({ message: "Invalid credentials" });
    }

    const secret = user.tfa_secret !== "" ? user.tfa_secret : req.body.secret;

    const verified = speakeasy.totp.verify({
      secret,
      encoding: "ascii",
      token: req.body.code,
    });

    if (!verified) {
      return res.status(400).send({ message: "Invalid credentials" });
    }

    if (user.tfa_secret === "") {
      await repository.update(id, { tfa_secret: secret });
    }

    // Access Token
    const accessToken = sign({ id }, process.env.ACCESS_TOKEN_SECRET_KEY, {
      expiresIn: "30s",
    });

    // Refresh Token
    const refreshToken = sign({ id }, process.env.REFRESH_TOKEN_SECRET_KEY, {
      expiresIn: "1w",
    });

    res.cookie("access_token", accessToken, {
      httpOnly: true, //Only accessible on backend
      maxAge: 24 * 60 * 60 * 1000, //1 day
    });

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, //1 day
    });

    res.send({ message: "success" });
  } catch (e) {
    return res.status(400).send({ message: "Invalid credentials" });
  }
};

export const authenticatedUser = async (req: Request, res: Response) => {
  const { password, tfa_secret, ...user } = req["user"];
  res.send(user);
};

export const refresh = async (req: Request, res: Response) => {
  try {
    const jwt = req.cookies["refresh_token"];

    const payload: any = verify(jwt, process.env.REFRESH_TOKEN_SECRET_KEY);

    if (!payload) {
      return res.status(401).send({ message: "Unauthenticated" });
    }

    const accessToken = sign(
      { id: payload.id },
      process.env.ACCESS_TOKEN_SECRET_KEY,
      {
        expiresIn: "30s",
      }
    );

    res.cookie("access_token", accessToken, {
      httpOnly: true, //Only accessible on backend
      maxAge: 24 * 60 * 60 * 1000, //1 day
    });

    res.send({ message: "success" });
  } catch (e) {
    return res.status(401).send({ message: "Unauthenticated" });
  }
};

export const logout = async (req: Request, res: Response) => {
  res.cookie("access_token", "", { maxAge: 0 });
  res.cookie("refresh_token", "", { maxAge: 0 });

  res.send({ message: "success" });
};

export const updateInfo = async (req: Request, res: Response) => {
  const user = req["user"];

  const repository = getManager().getRepository(User);

  await repository.update(user.id, req.body);

  const { password, ...data } = await repository.findOne(user.id);

  res.send(data);
};

export const updatePassword = async (req: Request, res: Response) => {
  const user = req["user"];
  if (req.body.password !== req.body.confirm_password) {
    return res.status(400).send({
      message: "Password do not match",
    });
  }

  const repository = getManager().getRepository(User);

  await repository.update(user.id, {
    password: await bcrypt.hash(req.body.password, 10),
  });

  const { password, ...data } = user;

  res.send(data);
};
