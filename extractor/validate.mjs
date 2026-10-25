// Validator: checks any extractor's output (rules-based or LLM) against the memo. Returns a list of problems; empty means clean.
import { CATEGORIES, NUM, parseNumber, endDate, findDates } from "./extract.mjs";

export function validatePromises(memo, promises) {
  const problems = [], seen = new Set();
  for (const x of promises) {
    const id = x.id || "(no id)", p = (m) => problems.push({ id, problem: m });
    if (seen.has(id)) p("duplicate id"); seen.add(id);
    if (!CATEGORIES.includes(x.category)) p(`category "${x.category}" is not in the fixed list`);
    const q = typeof x.quote === "string" ? x.quote : "";
    if (!q || !memo.includes(q)) p("quote is not an exact substring of the memo");
    if (typeof x.testable !== "boolean") p("testable must be true or false");
    if (x.testable === false && !String(x.reason || "").trim()) p("untestable promise has no reason");
    const pr = x.parameters || {}, lower = q.toLowerCase();
    const nums = new Set([...q.matchAll(new RegExp(NUM, "gi"))].map((m) => parseNumber(m[0])).filter((n) => n !== null));
    const need = (cond, m) => { if (x.testable && !cond) p(m); };
    switch (x.category) {
      case "HOLDER_CAP":
        if (pr.statedNumber !== undefined) {
          if (!nums.has(pr.statedNumber)) p("holder number does not appear in the quote");
          if (pr.maxHolders !== (pr.comparator === "FEWER_THAN" ? pr.statedNumber - 1 : pr.statedNumber)) p("maxHolders does not follow from the stated number");
        }
        need(pr.maxHolders > 0, "testable holder cap needs maxHolders"); break;
      case "SUPPLY_CAP":
        if (pr.statedNumber !== undefined && !nums.has(pr.statedNumber)) p("supply number does not appear in the quote");
        if (pr.maxSupply !== pr.statedNumber) p("maxSupply differs from the stated number");
        need(pr.maxSupply > 0, "testable supply cap needs maxSupply"); break;
      case "LOCKUP":
        if (pr.duration && pr.derivedFrom !== "anniversary" && !nums.has(pr.duration.value)) p("duration does not appear in the quote");
        if (pr.anchor) {
          const aq = pr.anchor.quote || "";
          if (!memo.includes(aq)) p("anchor quote is not an exact substring of the memo");
          if (!findDates(aq).some((d) => d.iso === pr.anchor.date)) p("anchor date does not appear in the anchor quote");
          if (pr.duration && pr.endsAt !== endDate(pr.anchor.date, pr.duration)) p("endsAt does not follow from the anchor date and duration");
        }
        need(!!pr.endsAt, "testable lock-up needs an end date"); break;
      case "JURISDICTION_BLOCK":
        for (const n of pr.blocked || []) if (!lower.includes(n.toLowerCase()) && !(pr.qualifier && /u\.?s\.?|united states/i.test(q))) p(`"${n}" does not appear in the quote`);
        need((pr.blocked || []).length > 0, "testable jurisdiction block needs at least one name"); break;
      case "TRANSFER_RESTRICTION":
        for (const c of pr.recipientClasses || []) if (!lower.includes(c.toLowerCase().replace("non-u.s.", "non-u")) && !/non-?u/i.test(q)) p(`recipient class "${c}" does not appear in the quote`);
        need((pr.recipientClasses || []).length > 0 || !!pr.approval, "testable transfer restriction needs a recipient class or approval"); break;
      case "FORCED_TRANSFER_OR_FREEZE":
        need((pr.powers || []).length > 0 && !!pr.actor, "testable freeze or forced transfer needs powers and an actor"); break;
      case "PAUSABILITY":
        need(!!pr.direction, "testable pausability needs a direction"); break;
    }
  }
  return problems;
}
