# Sophos Firewall Rules for Home Assistant

Discover IPv4 and IPv6 firewall rules and expose the rules you select as Home Assistant switches. Each switch shows whether the rule is enabled on the firewall and can be used in dashboards and automations.

**Requires Sophos Firewall OS (SFOS) 23.0 or later.** SFOS 23.0 introduced the configuration REST API used by this integration. Physical XG Series appliances top out at SFOS 20.0 and cannot run this integration. [SFOS 23.0 release notes](https://docs.sophos.com/releasenotes/output/en-us/nsg/sf_230_rn.html) · [XG firmware support](https://docs.sophos.com/releasenotes/output/en-us/nsg/sf_200_rn.html)

The original XML-based Sophos XG Firewall Rule Control integration (`sophos_xg_rules`) is obsolete. This repository now provides its REST-only replacement (`sophos_firewall_rules`). SNMP sensors are provided independently by [`sophos_xg`](https://github.com/istvanSA/sophos_xg).

## Requirements

- Home Assistant 2026.1 or later.
- Network access from Home Assistant to the firewall's HTTPS admin port (default `4444`).
- Under **Administration → API access**, enable API access and allow the Home Assistant server's source IP.
- A Sophos REST API key from an administrator profile with permission to read and update firewall rules. Setup checks read access. The firewall checks write permission when you use a switch. [Sophos REST API access and API keys](https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/APIRestAPI/APIAccessAndKeys/index.html)

## Install and configure

1. In HACS, add [`istvanSA/SophosXG-Rules`](https://github.com/istvanSA/SophosXG-Rules) as a custom repository of category **Integration** and download **Sophos Firewall Rules**. For manual installation, copy `custom_components/sophos_firewall_rules` into your Home Assistant `config/custom_components` directory.
2. Restart Home Assistant. Under **Settings → Devices & services → Add integration**, select **Sophos Firewall Rules**.
3. Enter the firewall hostname or IP, HTTPS admin port, and REST API key. Certificate verification is enabled by default. Use a trusted certificate whose name matches the address used by Home Assistant.
4. Select the rules to expose. The switches appear under the firewall device. Use **Configure** to reload the list and change your selection.

Switch **On** means the rule is enabled, whether the rule allows or blocks traffic. The integration polls once a minute while switches are in use and reads the rule back after a toggle. A missing rule or failed poll makes the affected switches unavailable. Home Assistant prompts for a replacement key if the firewall rejects the current one with HTTP 401.

## Edit a rule from a dashboard

The integration registers the card automatically when Home Assistant loads it. After updating and restarting Home Assistant, refresh any open dashboard tab. As a Home Assistant administrator, edit a dashboard and add the **Sophos Firewall Rule** card. You can also add it with this manual card configuration.

```yaml
type: custom:sophos-firewall-rule-card
```

Choose one of the rules selected in the integration. The card shows its status and action, the assigned application and web filters, the traffic shaping policy, and **Block QUIC**. The dropdowns use policies available on the firewall. Policy editing applies to standard allow rules. The API key needs read access to the policy catalogs to populate the dropdowns.

**Apply** sends your edits to Sophos and verifies the resulting settings. **Cancel** discards pending edits. Use **Refresh** to load changes made in Sophos or Home Assistant since you opened the rule.

For automations, target the rule's existing `switch` entity with **Turn on** or **Turn off**. The card is optional.

## Replace an existing XML installation

Before uninstalling the old integration, note its entity IDs and the dashboard cards and automations that reference them. Remove the old integration entry, install the REST integration, and select the same rules. Then update the references to the new switches, or assign the previous entity IDs to the new switches once those IDs are free.

## License

[MIT](LICENSE)
