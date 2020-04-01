module.exports = {
  getError(errors, propName) {
    try {
      return errors.mapped()[propName].msg;
    } catch (err) {
      return "";
    }
  }
};
