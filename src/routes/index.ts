import { Router } from "express";
import {
  register,
  login,
  authenticatedUser,
  logout,
  updateInfo,
  updatePassword,
  refresh,
  TwoFactor,
} from "../controller/auth.controller";
import { authMiddleware } from "../middleware/auth.middleware";
import { Forgot } from "../controller/forgot.controller";

export const routes = (router: Router) => {
  router.post("/api/register", register);
  router.post("/api/login", login);
  router.post("/api/two-factor", TwoFactor);
  router.post("/api/refresh", refresh);
  router.get("/api/user", authMiddleware, authenticatedUser);
  router.post("/api/logout", logout);
  router.put("/api/users/info", authMiddleware, updateInfo);
  router.put("/api/users/password", authMiddleware, updatePassword);

  router.post("/api/forgot", Forgot);
};
