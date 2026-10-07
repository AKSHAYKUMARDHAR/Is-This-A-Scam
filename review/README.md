# Review kit

Three checks the automated eval can't do on its own. Each takes 30 to 60 minutes. Open the CSV files in Excel or Google Sheets (File > Import); they are saved with a byte-order mark so Hindi and Bengali show correctly. When you save, keep the format as CSV (UTF-8).

## 1. Hindi and Bengali wording (a native speaker)

| File | What it is |
|---|---|
| `explanations_hi.csv`, `explanations_bn.csv` | 30 result cards per language, exactly as the app shows them: the message, the verdict, and the explanation the model wrote. 14 "Likely scam", 9 "Can't tell", 7 "No scam signs found". |
| `ui_text.csv` | Every fixed piece of text in the app (127 rows): verdict labels, headlines, scam types, next steps, how-to-check tips, red-flag explanations, the "already paid" steps and the interface. English is there for reference. |

For each row, fill in:

- **meaning correct?** `yes` or `no`. Does it say the same thing as the English would, with nothing wrong or misleading?
- **reads naturally?** 1 to 5. Would a normal reader say it this way, or is it bookish, machine-translated or full of words people don't use?
- **better wording**, if you have one.

Look out for wrong meanings first, then stiff or overly formal Hindi or Bengali, English words a typical reader wouldn't know, and tone (it should be calm and direct, never alarming).

**Pass mark:** no wrong meanings, and an average of 4 or more for naturalness. When done, save the files here and ask Claude to "apply the review". Fixed text in `ui_text.csv` gets changed directly. For the model's explanations, recurring problems go into the prompt as instructions, and the eval is re-run.

## 2. A second labeller (someone other than you)

Give them **only `labelling_sheet.csv`**: 60 messages from the test sets, with the answers removed. Don't share `labelling_key.csv` or the `eval/data/` folder.

Instructions for them. For each message, choose one label:

- **scam:** it is trying to cheat the reader (money, an OTP or PIN, personal details, installing an app, and so on).
- **genuine:** a normal message from a real sender. Doing what it says is safe.
- **ambiguous:** you can't tell from the message alone. It could be either.

If it's a scam, add a type: `investment`, `digital_arrest`, `bank_kyc`, `fake_payment`, `fake_job`, `family_emergency`, `parcel`, `bill_challan` or `other`.

Then compare:

```bash
python -m eval.agreement review/labelling_sheet.csv
```

This prints the agreement rate, Cohen's kappa, a confusion table and every disagreement. A kappa of 0.6 or more means the labels are dependable; below that, the eval numbers depend on who labelled. Some rows come from the frozen test sets, so a disagreement is reported as label uncertainty, never fixed by changing a test label after a run.

## 3. Real messages (you)

Collect 30 to 50 real messages in `real_messages_template.csv` (or any CSV with the same columns): scams, normal messages and unclear ones, from your own SMS, WhatsApp and spam folders. Paste each one exactly as received, one per row, with your best-guess label.

**Privacy:** ask before using messages someone else received. Keep the filled file outside git: put it outside the repo, or in `data/real/`, which git ignores. The ingest step masks phone, card, account, Aadhaar, PAN and OTP numbers, but not names or addresses.

```bash
python -m eval.ingest_real path/to/real_messages.csv     # writes data/real/real.jsonl, masked
# read data/real/real.jsonl and replace names and addresses with [name] / [address]
python -m eval.run_eval data/real/real.jsonl --note "real messages, batch 1"
```

Each message uses up to 2 model calls (the Gemini free tier allows 500 a day per model).

## Regenerate the sheets

```bash
python -m eval.make_review_sheets      # built from cached model answers, no model calls
```
