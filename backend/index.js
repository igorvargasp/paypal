const express = require("express");
const cors = require("cors");
const paypal = require("@paypal/checkout-server-sdk");
const app = express();
app.use(cors());
app.use(express.json());

const clientId =
  "AWIKHmh7GrjGmYCZLkvrN3-lDpP6Q_7_DauHpzPXr61bTxedbKEJPN1bhEf6UxOCfJltmJvN2bS2XKk0"; // THIS IS ONLY FOR TEST REASONS
const clientSecret =
  "EIXovnq24u2-f4a1y5nKbH1loyjQt997mVf9B3Pr7GhaSXDgFHViZNM2Gd9ETRI8JwiXHKEm9K0Ag-Nv"; // THIS IS ONLY FOR TEST REASONS

const environment = new paypal.core.SandboxEnvironment(clientId, clientSecret);
const client = new paypal.core.PayPalHttpClient(environment);

app.post("/completePurchase", async (req, res) => {
  try {
    const orderID = req.body.orderID;

    const request = new paypal.orders.OrdersCaptureRequest(orderID);
    request.requestBody({});

    const capture = await client.execute(request);

    return res.json({ transactionID: capture.result.id });
  } catch (error) {
    console.error("Error completing the purchase:", error);
    res.status(500).send("Error completing the purchase");
  }
});
// Start the server
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
