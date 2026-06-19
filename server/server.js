import express from "express";
import cors from "cors";
import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

const app = express();

app.use(cors());

app.get("/api/abuse/:ip", async (req, res) => {
  try {

    const ip = req.params.ip;

    const API_KEY = process.env.ABUSE_API_KEY;

    const url = "https://api.abuseipdb.com/api/v2/check";

    const response = await axios.get(url, {
      headers: {
        Key: API_KEY,
        Accept: "application/json",
      },

      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
      },
    });

    res.json(response.data);

  } catch (error) {

    console.log(error);

    res.status(500).json({
      error: "Failed to fetch abuse data",
    });
  }
});

app.get("/api/censys/:ip", async (req, res) => {
  try {
    const ip = req.params.ip;

    const response = await axios.get(
      `https://api.platform.censys.io/v3/global/asset/host/${ip}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.CENSYS_TOKEN}`,
        },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.log("STATUS:", error.response?.status);
    console.log("DATA:", error.response?.data);
    console.log("MESSAGE:", error.message);

    res.status(500).json({
      error: error.response?.data || error.message,
    });
  }
});

app.get("/api/virustotal/:ip", async (req, res) => {
  try {
    const ip = req.params.ip;

    const response = await axios.get(
      `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
      {
        headers: {
          "x-apikey": process.env.VIRUSTOTAL_API_KEY,
        },
      }
    );

    res.json(response.data);

  } catch (error) {
    console.log(error.response?.data || error.message);

    res.status(500).json({
      error: "Failed to fetch VirusTotal data",
    });
  }
});

app.get("/api/blacklists/:ip", async (req, res) => {
  const ip = req.params.ip;

  const result = {
    abuseipdb: false,
    alienvault: false,
    greynoise: false,
  };

  try {
    // AlienVault
    const otx = await axios.get(
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`
    );

    if (otx.data.pulse_info.count > 0) {
      result.alienvault = true;
    }

    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Blacklist lookup failed",
    });
  }
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});