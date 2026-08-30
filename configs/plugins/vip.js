import BasePlugin from './base-plugin.js';

export default class vip extends BasePlugin {

    static get description() {
        return 'Check vip status';
    }

    static get defaultEnabled() {
        return true;
    }

    static get optionsSpecification() {
        return {
            command: {
                required: false,
                description: 'Check vip',
                default: 'vip',
            },
            sqstat_key: {
                required: false,
                description: 'API Key for Sqstat panel',
                default: '',
            }
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
        const id = info.player.steamID;

        try {
            const [pstnExpire, sqstatExpire] = await Promise.all([
                this.checkPstnSquad(id),
                this.checkSqStat(id)
            ]);

            const maxExpire = Math.max(pstnExpire, sqstatExpire);

            if (maxExpire === -1) {
                await this.server.rcon.warn(id, `На данный момент у вас нет VIP'а`);
            } else if (maxExpire === Infinity) {
                await this.server.rcon.warn(id, `У вас бессрочный VIP!`);
            } else {
                const date = new Date(maxExpire);
                const d = String(date.getDate()).padStart(2, '0');
                const m = String(date.getMonth() + 1).padStart(2, '0');
                const h = String(date.getHours()).padStart(2, '0');
                const min = String(date.getMinutes()).padStart(2, '0');

                await this.server.rcon.warn(id, `Дата окончания VIP : ${d}.${m} ${h}:${min}`);
            }
        } catch (e) {

        }
    }

    async checkPstnSquad(id) {
        try {
            const res = await fetch('https://pstnsquad.ru:1002/v1/api/privileged/privileges/?steam_id=' + id, {
                headers: { "Authorization": "Token 541c8b9e99b329a2f57551b728ad38e7aef9b803" }
            });
            const data = await res.json();

            if (!data.results || data.results.length === 0) return -1;

            const user = data.results[0];
            if (!user.is_active) return -1;
            if (user.date_of_end == null) return Infinity;

            return new Date(user.date_of_end).getTime();
        } catch (e) {
            return -1;
        }
    }

    async checkSqStat(id) {
        const sqstat_key = "b7738108d156e350730daa79e55fdf6f" ;

        try {
            const res = await fetch(`https://pstn.sqstat.ru/api/player/info.php?key=${sqstat_key}&steam_id=${id}`);
            const data = await res.json();


            const playerInfo = data.info || data;

            const groupId = playerInfo.group_id;

            if (groupId === null || groupId === undefined) return -1;

            if (String(groupId) !== '3') return Infinity;

            if (String(playerInfo.expire) === '0') return Infinity;

            return parseInt(playerInfo.expire) * 1000;
        } catch (e) {
            return -1;
        }
    }
}
