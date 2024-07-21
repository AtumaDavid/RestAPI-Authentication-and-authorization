const { Router } = require("express");
const {
  register,
  stay,
  login,
  loggedin,
  admin,
  moderators,
  refreshtoken,
  logout,
  twoFactor,
  setupTwoFactor,
  enableTwoFactor,
  login2fa,
} = require("../controllers/controller");
const ensureAuthenticated = require("../middleware/ensureAuthenticated");
const authorize = require("../middleware/authorize");

const router = Router();

router.get("/", stay);
router.post("/api/auth/register", register);
router.post("/api/auth/login", login);

// refresh token
router.post("/api/auth/refresh-token", refreshtoken);
// The middleware ensureAuthenticated is responsible for verifying that a user is authenticated before allowing them access to certain routes.
router.get("/api/users/loggedin", ensureAuthenticated, loggedin);

router.get("/api/admin", ensureAuthenticated, authorize(["admin"]), admin);
router.get(
  "/api/moderator",
  ensureAuthenticated,
  authorize(["admin", "moderator"]),
  moderators
);

// router.get("api/auth/2fa/generate", ensureAuthenticated, twoFactor);
router.get("/api/auth/2fa/setup", ensureAuthenticated, setupTwoFactor);
router.post("/api/auth/2fa/enable", ensureAuthenticated, enableTwoFactor);
router.post("/api/auth/login/2fa", login2fa);

router.get("/api/auth/logout", ensureAuthenticated, logout);

module.exports = router;
