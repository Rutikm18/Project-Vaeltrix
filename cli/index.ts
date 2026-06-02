#!/usr/bin/env node
import { Command }                from "commander";
import { buildScanCommand }       from "./commands/scan";
import { buildFindingsCommand }   from "./commands/findings";
import { buildLoginCommand }      from "./commands/login";
import { buildLogoutCommand }     from "./commands/logout";
import { buildWhoamiCommand }     from "./commands/whoami";
import { buildAdminCommand }      from "./commands/admin";
import { buildAskCommand }        from "./commands/ask";
import { buildStatusCommand }     from "./commands/status";
import { buildEngagementCommand } from "./commands/engagement";
import { buildReportCommand }     from "./commands/report";

const VERSION = "0.4.0";

const program = new Command();

program
  .name("adversa")
  .description("Network VAPT Platform — CLI")
  .version(VERSION, "-v, --version");

// ── Auth
program.addCommand(buildLoginCommand());
program.addCommand(buildLogoutCommand());
program.addCommand(buildWhoamiCommand());

// ── Engagements
program.addCommand(buildEngagementCommand());

// ── Scanning
program.addCommand(buildScanCommand());
program.addCommand(buildStatusCommand());

// ── Analysis & Reporting
program.addCommand(buildFindingsCommand());
program.addCommand(buildAskCommand());
program.addCommand(buildReportCommand());

// ── Admin
program.addCommand(buildAdminCommand());

program.parseAsync(process.argv).catch((e: unknown) => {
  const msg = e instanceof Error ? e.message : String(e);
  process.stderr.write(`\x1b[1;31m[ERR]\x1b[0m ${msg}\n`);
  process.exit(1);
});
