# SimplifIQ Flow V2

Clean implementation of:

```text
HTML form -> business email check -> OTP verification -> backend validation -> optional search -> Gemini -> PDF -> Drive -> Google Sheet -> Email
```

## Start

```bash
cd simplifiq-flow-v2
copy .env.example .env
npm start
```

Open:

```text
http://localhost:3000
```

## Required Setup

Fill `.env`:

```env
GEMINI_API_KEY=your_key
GEMINI_MODEL=gemini-2.5-flash

GOOGLE_CLIENT_EMAIL=your-service-account@project.iam.gserviceaccount.com
GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

GOOGLE_DRIVE_FOLDER_ID=your_drive_folder_id
GOOGLE_SHEET_ID=your_sheet_id
GOOGLE_SHEET_RANGE=Sheet1!A:J
```

Then share the Drive folder and Google Sheet with the service account email as **Editor**.

For OAuth, connect Google from the app:

```text
http://localhost:3020/auth/google
```

Required OAuth scopes:

```text
https://www.googleapis.com/auth/drive.file
https://www.googleapis.com/auth/spreadsheets
https://www.googleapis.com/auth/gmail.send
```

Google Search is optional. Leave these blank if you do not need it:

```env
GOOGLE_SEARCH_API_KEY=
GOOGLE_SEARCH_CX=
```

## Test Config

Open:

```text
http://localhost:3000/api/config-status
```
