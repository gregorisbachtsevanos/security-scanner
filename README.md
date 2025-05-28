# Daily.dev Post Image Scraper

A simple Node.js script that fetches the main post image from a Daily.dev article URL using Cheerio and Axios.

## 📦 Setup

1. Clone the repo or create a new project.
2. Install dependencies:

```
npm install
```

3. Create a .env file (optional) or edit the URL directly in scraper.js.

## 🚀 Usage

Update the postUrl inside scraper.js with your desired Daily.dev post URL.

Then run:

```
npm start
```

The script will log the srcset and src of the main post image with class:

```
<img class="mobileXXL:self-start mt-4 w-full mobileXL:w-60 rounded-12 h-40 object-cover" ... />
```

## 🛠 Dependencies

• Axios\
• Cheerio

