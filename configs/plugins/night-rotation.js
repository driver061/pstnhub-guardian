import BasePlugin from './base-plugin.js';
import fs from 'fs';
import path from 'path';

export default class NightRotation extends BasePlugin {
    static get description() {
        return 'Automated Night Mode Rotation with History and Faction Filtering';
    }

    static get defaultEnabled() {
        return false;
    }

    static get optionsSpecification() {
        return {
            enabled: {
                required: false,
                description: 'Enable the plugin',
                default: false
            },
            historyFile: {
                required: false,
                description: 'File path to store layer history',
                default: 'layer-history.json'
            },
            historyLength: {
                required: false,
                description: 'Number of recent maps to remember for exclusion',
                default: 4
            },
            startTime: {
                required: false,
                description: 'Start time for night mode (HH:MM)',
                default: '21:30'
            },
            endTime: {
                required: false,
                description: 'End time for night mode (HH:MM)',
                default: '09:00'
            },
            delay: {
                required: false,
                description: 'Delay in milliseconds after game start before processing',
                default: 45000
            },
            saveDelay: {
                required: false,
                description: 'Buffer (ms) AFTER saving history but BEFORE setting the next layer',
                default: 5000
            },
            rotationConfig: {
                required: true,
                description: 'List of allowed maps, layers, and factions for night mode',
                default: []
            }
        };
    }

    constructor(server, options, connectors) {
        super(server, options, connectors);
        this.onNewGame = this.onNewGame.bind(this);
        this.processRotation = this.processRotation.bind(this);
    }

    async mount() {
        this.server.on('NEW_GAME', this.onNewGame);
        await this.processRotation(true);
    }

    async unmount() {
        this.server.removeListener('NEW_GAME', this.onNewGame);
    }

    async onNewGame() {
        setTimeout(() => this.processRotation(false), this.options.delay);
    }

    async processRotation(isCatchup = false) {
        try {
            const serverInfoRaw = await this.server.rcon.execute('ShowServerInfo');
            if (!serverInfoRaw) return;

            let info;
            try {
                info = JSON.parse(serverInfoRaw);
            } catch (e) {
                return;
            }

            const currentLayerRaw = info.MapName_s;
            const currentTeam1Raw = info.TeamOne_s;
            const currentTeam2Raw = info.TeamTwo_s;

            if (!currentLayerRaw || !currentTeam1Raw || !currentTeam2Raw) return;

            const currentMap = currentLayerRaw.split('_')[0];
            const currentTeam1 = currentTeam1Raw.split('_')[0];
            const currentTeam2 = currentTeam2Raw.split('_')[0];

            const serverId = this.server.id ? `-${this.server.id}` : '';
            const fileParts = path.parse(this.options.historyFile);
            const uniqueFileName = `${fileParts.name}${serverId}${fileParts.ext}`;
            const historyPath = path.resolve(fileParts.dir, uniqueFileName);

            let history = { maps: [], factions: [] };

            // --- LOAD HISTORY ---
            if (fs.existsSync(historyPath)) {
                try {
                    history = JSON.parse(fs.readFileSync(historyPath, 'utf8'));
                } catch (err) { }
            }

            // Enforce History Limit Immediately
            if (history.maps.length > this.options.historyLength) {
                history.maps = history.maps.slice(0, this.options.historyLength);
            }
            if (history.factions && history.factions.length > this.options.historyLength) {
                history.factions = history.factions.slice(0, this.options.historyLength);
            }

            // Check the most recent map (Index 0 is now the freshest)
            const lastRecordedMap = history.maps.length > 0 ? history.maps[0] : null;

            // If we are in catchup mode and the current layer is already recorded, stop.
            if (lastRecordedMap && lastRecordedMap.layer === currentLayerRaw && isCatchup) return;

            let historyUpdated = false;

            // --- STEP 1: Update History Object (Fresh to Old) ---
            if (!lastRecordedMap || lastRecordedMap.layer !== currentLayerRaw) {
                // Add to start of array (unshift)
                history.maps.unshift({ name: currentMap, layer: currentLayerRaw, timestamp: Date.now() });
                
                if (!history.factions) history.factions = [];
                history.factions.unshift({ t1: currentTeam1, t2: currentTeam2 });

                // Trim to size
                if (history.maps.length > this.options.historyLength) {
                    history.maps = history.maps.slice(0, this.options.historyLength);
                }
                if (history.factions.length > this.options.historyLength) {
                    history.factions = history.factions.slice(0, this.options.historyLength);
                }

                historyUpdated = true;
                
                // --- STEP 2: Save to Disk IMMEDIATELY ---
                fs.writeFileSync(historyPath, JSON.stringify(history, null, 2));
            }

            if (!this.isNight()) return;

            if (currentLayerRaw.toLowerCase().includes('seed')) return;

            // --- STEP 3: Buffer (The Fix) ---
            // We wait here to ensure the write is effectively "done" and state is settled before calculating next layer
            if (historyUpdated && this.options.saveDelay > 0) {
                await new Promise(resolve => setTimeout(resolve, this.options.saveDelay));
            }

            // --- STEP 4: Set Next Layer ---
            // We pass the updated 'history' object which definitely contains the current game now
            await this.setNextLayer(history);

        } catch (err) {
            console.error('NightRotation Error:', err);
        }
    }

    async setNextLayer(history) {
        const config = this.options.rotationConfig;
        if (!config || config.length === 0) return;

        const playedMapNames = history.maps.map(m => m.name);
        
        let availableMaps = config.filter(mapConfig => !playedMapNames.includes(mapConfig.mapName));

        if (availableMaps.length === 0) {
            availableMaps = [...config];
        }

        this.shuffleArray(availableMaps);

        // Get the most recent factions (Index 0)
        const lastFactions = history.factions && history.factions.length > 0 ? history.factions[0] : null;

        let selectedMapConfig = null;
        let selectedMatchup = null;

        // Standard Faction Filter (Avoid repeating last played factions)
        for (const mapConfig of availableMaps) {
            if (!mapConfig.factions || mapConfig.factions.length === 0) continue;

            let validMatchups = mapConfig.factions;

            if (lastFactions) {
                validMatchups = mapConfig.factions.filter(matchup => {
                    const [teamA, teamB] = matchup;
                    const teamA_Played = (teamA === lastFactions.t1 || teamA === lastFactions.t2);
                    const teamB_Played = (teamB === lastFactions.t1 || teamB === lastFactions.t2);
                    return !teamA_Played && !teamB_Played;
                });
            }

            if (validMatchups.length > 0) {
                selectedMapConfig = mapConfig;
                selectedMatchup = validMatchups[Math.floor(Math.random() * validMatchups.length)];
                break; 
            }
        }

        // Fallback
        if (!selectedMapConfig) {
            selectedMapConfig = availableMaps[Math.floor(Math.random() * availableMaps.length)];
            const allMatchups = selectedMapConfig.factions || [];
            if (allMatchups.length > 0) {
                selectedMatchup = allMatchups[Math.floor(Math.random() * allMatchups.length)];
            }
        }

        if (!selectedMapConfig || !selectedMatchup) return;

        if (!selectedMapConfig.layers || selectedMapConfig.layers.length === 0) return;
        const selectedLayer = selectedMapConfig.layers[Math.floor(Math.random() * selectedMapConfig.layers.length)];

        const [faction1, faction2] = selectedMatchup;
        const command = `AdminSetNextLayer ${selectedLayer} ${faction1}+CombinedArms ${faction2}+CombinedArms`;

        await this.server.rcon.execute(command);
    }

    isNight() {
        const timeString = new Date().toLocaleTimeString('en-GB', { timeZone: 'Europe/Moscow', hour12: false });
        const [currentHour, currentMinute] = timeString.split(':').map(Number);
        const currentTime = currentHour * 60 + currentMinute;

        const [startHour, startMinute] = this.options.startTime.split(':').map(Number);
        const [endHour, endMinute] = this.options.endTime.split(':').map(Number);

        const startTime = startHour * 60 + startMinute;
        const endTime = endHour * 60 + endMinute;

        if (endTime < startTime) {
            return currentTime >= startTime || currentTime < endTime;
        } else {
            return currentTime >= startTime && currentTime < endTime;
        }
    }

    shuffleArray(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
    }
}