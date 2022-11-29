const argon2 = require("argon2");

const hashingOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 5,
  parallelism: 1,
};

const hashPassword = (req, res, next) => {
  const password = req.body.password;

  argon2
    .hash(password, hashingOptions)
    .then((hashedPassword) => {
      // console.log(hashedPassword);

      req.body.hashedPassword = hashedPassword;
      delete req.body.password;

      next();
    })
    .verify(hashedPassword, password)
    .catch((err) => {
      console.error(err);
      res.sendStatus(500);
    });
};

const verifyPassword = (req, res) => {
  res.send(req.user);
  console.log(req.user);
};

module.exports = {
  hashPassword,
  verifyPassword,
};
