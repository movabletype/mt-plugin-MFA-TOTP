/* eslint-env node */
const path = require("path");

const config = {
  plugins: [],
  mode: "development",
  entry: {
    "enable_dialog.min": ["./mt-static/plugins/MFA-TOTP/src/enable_dialog.ts"],
    "disable_dialog.min": ["./mt-static/plugins/MFA-TOTP/src/disable_dialog.ts"]
  },
  resolve: {
    extensions: [".js", ".jsx", ".ts", ".tsx"],
    modules: ["node_modules", "mt-static/plugins/MFA-TOTP/src"],
  },
  externals: {
    jquery: "jQuery",
  },
  output: {
    path: path.resolve(__dirname, "mt-static/plugins/MFA-TOTP/dist"),
    filename: "[name].js",
  },
  module: {
    rules: [
      {
        test: /\.(j|t)sx?$/,
        exclude: /node_modules/,
        use: {
          loader: "babel-loader",
        },
      },
      { test: /\.svg$/, type: "asset/inline" },
    ],
  },
  watchOptions: {
    ignored: ["node_modules/**"],
  },
};

if (process.env.NODE_ENV === "development") {
  config.devtool = "inline-source-map";
}

module.exports = config;
