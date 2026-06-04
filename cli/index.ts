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
import { buildInteractiveCommand, runInteractive } from "./commands/interactive";
import { buildDoctorCommand }    from "./commands/doctor";
import { AdversaError }          from "../lib/errors";

const VERSION = "0.6.0";

const program = new Command();

program
  .name("adversa")
  .description("Network VAPT Platform — CLI (run with no arguments for interactive mode)")
  .version(VERSION, "-v, --version")
  .action(async () => {
    // No subcommand → launch interactive wizard.
    await runInteractive();
  });

// ── Interactive (alias: menu / start)
program.addCommand(buildInteractiveCommand());

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

// ── Diagnostics
program.addCommand(buildDoctorCommand());

program.parseAsync(process.argv).catch((e: unknown) => {
  // Typed errors render themselves with title + fix; raw errors get a generic
  // wrapping plus a pointer to the doctor command.
  if (e instanceof AdversaError) {
    process.stderr.write(e.render() + '\n');
    process.exit(1);
  }
  const msg = e instanceof Error ? e.message : String(e);
  process.stderr.write(`\x1b[1;31m✗ ${msg}\x1b[0m\n`);
  process.stderr.write(`  \x1b[1;36mFix:\x1b[0m run \`./run.sh cli doctor\` for diagnostics.\n`);
  process.exit(1);
});
