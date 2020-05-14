module.exports = {
  root: true,
  env: {
    commonjs: true,
  },
  parser: "@typescript-eslint/parser",
  plugins: ["@typescript-eslint"],
  rules: {
    "@typescript-eslint/camelcase": [
      "error",
      {
        properties: "always",
        allow: [
          "client_id",
          "client_secret",
          "access_token",
          "grant_type",
          "redirect_uri",
          "email_verified",
          "confirm_token",
          "challenge_ts",
          "user_id",
          "fbtrace_id",
          "api_key",
          "event_type",
          "event_properties",
        ],
      },
    ],
    "@typescript-eslint/no-unused-vars": [
      "error"
    ],
    "@typescript-eslint/no-non-null-assertion": 0,
    "@typescript-eslint/ban-ts-ignore": 0,
    "@typescript-eslint/explicit-function-return-type": "off",
    "@typescript-eslint/no-explicit-any": "off"
  },
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/eslint-recommended",
    "plugin:@typescript-eslint/recommended",
  ],
};
