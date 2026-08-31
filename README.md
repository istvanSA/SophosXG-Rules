# Sophos XG Firewall Rule Control for Home Assistant

A custom Home Assistant integration to **enable/disable specific Sophos XG
(SFOS) firewall rules** as switch entities, using the Sophos XML API.

This is a companion to [`sophos_xg`](https://github.com/istvanSA/sophos_xg)
(SNMP monitoring). SNMP on Sophos XG is read-only, so toggling rules needs
the separate XML API instead - that's what this integration talks to. Kept
as its own repo/integration so it can be installed independently.

## How it works

The Sophos API has no partial update for a rule's status. Every toggle:

1. `Get`s the rule's full current XML by its exact **Name**.
2. Flips only the `<Status>` element (`Enable`/`Disable`).
3. `Set operation="update"`s that same XML back to the firewall.

Rule status is also polled periodically so the switch reflects changes made
elsewhere (e.g. the Sophos web admin).

## Prerequisites

- **API access enabled** on the firewall:
  `Backup & Firmware > API` (or `Administration > API access` on newer
  firmware) - turn it on and allow the IP address of your Home Assistant
  instance.
- **A dedicated API user** (recommended over reusing an admin account):
  `Authentication > Users` - create a user, type **Administrator**, with an
  administrator profile that has **read/write** rights to Firewall Rules.
- Know the **exact Name** of each firewall rule you want to control, as it
  appears in `Rules and policies` in the Sophos web admin. The API
  addresses rules by name, not by the numeric row/ID shown in the UI.

## Installation

### Method 1: HACS (custom repository)

1. Open **HACS** in Home Assistant.
2. Three dots (top right) > **Custom repositories**.
3. Add `https://github.com/istvanSA/sophos_xg_rules`, category **Integration**.
4. Find "Sophos XG Firewall Rule Control" in HACS and download it.
5. Restart Home Assistant.

### Method 2: Manual

1. Download the latest release / repo contents.
2. Copy `custom_components/sophos_xg_rules` into your Home Assistant
   `config/custom_components` directory.
3. Restart Home Assistant.

## Configuration

1. **Settings > Devices & Services > Add Integration**, search for
   "Sophos XG Firewall Rule Control".
2. Enter the firewall's **host/IP**, API **port** (default `4444`),
   **username**, **password**, and whether to verify the SSL certificate
   (leave this off if the firewall uses its default self-signed cert).
3. Once added, open the integration's **Configure** option to **add
   firewall rules by name**. Each added rule becomes a toggle switch
   entity. Rules can also be removed the same way.

## Notes / limitations

- Only the rule's enabled/disabled status is changed - no other rule
  settings are touched or need to be re-specified.
- If a configured rule is renamed or deleted on the firewall, its switch
  will show as unavailable until the rule is removed from the
  integration's options (or re-added under its new name).
- Credentials are stored in Home Assistant's config entry storage, as with
  any other integration.

## License

[MIT License](LICENSE)
