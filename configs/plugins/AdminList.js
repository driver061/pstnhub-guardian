import BasePlugin from './base-plugin.js';

export default class AdminList extends BasePlugin {
  static get description() {
    return (
      'This plugin allows you to list all admins online by typing a command in chat.'
    );
  }

  static get defaultEnabled() {
    return true;
  }

  static get optionsSpecification() {
    return {
      command : {
        required    : false,
        description : 'The command to listen for in chat.',
        default     : 'command',
      },
    };
  }

  constructor(server, options, connectors) {
    super(server, options, connectors);

    this.onChatCommand = this.onChatCommand.bind(this);
  }

  async mount() {
    this.server.on(`CHAT_COMMAND:${this.options.command}`, this.onChatCommand);
  }

  async unmount() {
    this.server.removeEventListener(`CHAT_COMMAND:${this.options.command}`, this.onChatCommand);
  }

  async onChatCommand(info) {	
    const admins = await this.server.getAdminsWithPermission('canseeadminchat');
    const list = [];
    for (const player of this.server.players) {
      if (admins.includes(player.steamID)) {
        list.push(player.name);
      }
    }
    
    await this.server.rcon.warn(info.player.steamID, `Admins online: ${list.join(', ')}`);
  }
}