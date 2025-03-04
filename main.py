import discord
import re
import json
import aiohttp
import asyncio
from discord import app_commands
from selenium import webdriver
from PIL import Image
import os

TOKEN = ''  # Your discord bot token goes here

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True


class aclient(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.synced = False

    async def on_ready(self):
        await self.wait_until_ready()
        if not self.synced:
            await tree.sync()
            self.synced = True
        print(f"We have logged in as {self.user}.")


client = aclient()
tree = app_commands.CommandTree(client)


def update_json(serverID, api_key):
    try:
        with open('data.json', 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        pass
    new_entry = {
        "api_key": api_key,
        "warn_list": {
        }
    }
    data[serverID] = new_entry

    with open('data.json', 'w') as file:
        json.dump(data, file, indent=4)


async def update_warning_list(serverID, name, userID):
    try:
        with open('data.json', 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        pass

    if name not in data[serverID]['warn_list']:
        data[serverID]['warn_list'][name] = 1
    else:
        data[serverID]['warn_list'][name] = data[serverID]['warn_list'][name] + 1
        warnings = data[serverID]['warn_list'][name]
        if int(warnings) > 2:
            userID: discord.Member
            await userID.kick(reason = 'Has sent 3 malicious links')
            data[serverID]['warn_list'][name] = 0  # reset the counter in case if the user re-joins the server

    with open('data.json', 'w') as file:
        json.dump(data, file, indent=4)


def setup(server_id, key):
    print(server_id)
    ApiKey = key
    if ApiKey == "" or len(ApiKey) < 30:
        return "Invalid VirusTotal API Key, try again or refer to the setup guide. (/help for the guide)"
    if ApiKey != 0:
        update_json(server_id, ApiKey)
        return "vSec has been set up with your API Key, don't share it with anybody!"


@tree.command(name="help", description="Setup guide")
async def self(interaction: discord.Interaction):
    embed = discord.Embed(title="Setup Guide", color=0x2ea4ff)
    embed.set_author(name="Bot created by @valkayuh")
    embed.add_field(name="",
                    value="1 - Use [this](https://www.golinuxcloud.com/find-discord-server-id/) guide to get your Server ID",
                    inline=False)
    embed.add_field(name="", value="2 - Use the /setup command and paste your Server ID in the first field",
                    inline=False)
    embed.add_field(name="",
                    value="3 - Go to [VirusTotal](https://www.virustotal.com/gui/join-us) and sign up, it's free!",
                    inline=False)
    embed.add_field(name="", value="4 - After you have made your account you need to click on your profile (top right)",
                    inline=False)
    embed.add_field(name="", value="5 - Click on 'API Key' and then copy the API Key", inline=False)
    embed.add_field(name="", value="6 - Now paste the API key in the second field and hit enter", inline=False)
    await interaction.response.send_message(embed=embed)


@tree.command(name="setup", description="Setup vSec")
async def self(interaction: discord.Interaction, server_id: str, key: str):
    await interaction.response.send_message(setup(server_id, key))


# Open the text file and read the words into a list
with open('codeListMerged.txt', 'r') as file:
    words = file.read().split(',')


async def analyse(link):
    async with aiohttp.ClientSession() as session:
        with open('data.json', 'r') as file:
            data = json.load(file)
            ApiKey = data.get(str(server_id), {}).get("api_key")

        print('ApiKey is:', ApiKey)
        print('server id inside analyse is:', server_id)
        url = "https://www.virustotal.com/api/v3/urls"
        params = {'url': link}
        headers = {'x-apikey': ApiKey}

        async with session.post(url, params=params, headers=headers) as response:
            if response.status != 200:
                return await status_code(await response.content.read())  # Check if the request is ok

            json_data = await response.json()
            url = json_data['data']['links']['self']  # extract the link only

            while True:
                async with session.get(url, headers=headers) as response:
                    json_data = await response.json()
                    if 'data' in json_data:
                        if json_data['data']['attributes']['status'] == "completed":
                            break
                    elif json_data['error']['message'] == "Quota exceeded":
                        print("!!!!!!!!!!Quota exceeded!!!!!!!!!!")
                        await status_code("Quota exceeded poggies!")
                        return ''
                    await asyncio.sleep(0.75)

        response_data = json_data['data']['attributes']['stats']  # get only the relevant stats
        modify_html_template(response_data)

        return response_data


@client.event
async def on_message(message):
    user_message = str(message.content)
    msg = user_message.lower()  # Mostly to help shorten the huge if statement needed for the search function

    if message.author == client.user:  # Making sure that the bot doesn't respond to its self
        return

    global server_id
    server_id = message.guild.id
    # print('server id is: ' f'{server_id}')

    global status_code  # Very jank yes but this is temporary™️

    async def status_code(response):
        await message.channel.send("We had trouble analysing the last message, error: " f"{response}")

    # Loop through each word in the list and check if it is in the string
    for word in words:
        if word.strip() in msg:
            domain_suffix = word.strip()
            pattern = r"\b\w+\{}\b".format(domain_suffix)  # filters the link out of the message
            msg = re.findall(pattern, msg)
            global link_for_report
            link_for_report = ''.join(msg) # used for the HTML generated report

            print(msg)
            task = asyncio.create_task(analyse(msg))
            # Wait for the task to complete
            report = await task

            if report['malicious'] != 0 or report['suspicious'] != 0:  # if statement that proceeds with the report only if it is flagged at least once
                # A bit of formatting
                del report['timeout']
                formatted_report = json.dumps(report, indent=4)
                await message.reply("Please note that after 3 warnings you get kicked!\nThe message contained a possibly malicious link! Here's a report on it:\n", file = analysis)
                await update_warning_list(str(message.guild.id), str(message.author), message.author) # updating warning list and kicking users with more than 3 warnings
                # await message.reply("The message contained a possibly malicious link! Here's a report on it:\n" f"{formatted_report}")
                # ^^^ this can be used as a fallback when image generation takes too long
            else:
                return


    # Generating the HTML embed
def modify_html_template(results):
    detections = results['malicious'] + results['suspicious']
    total = results['harmless'] + results['undetected'] + results['malicious'] + results['suspicious']
    ratio = (1 - detections / total) * 282.743

    with open('template.html', 'r') as template:
        html = template.read()

    with open('temporary.html', 'w') as temp:
        temp.write(html)

    with open('temporary.html', 'r') as temp:
        html_temp = temp.read()

    html_temp = html_temp.replace('highlighted-text">2',
                        f'highlighted-text">{detections}')
    html_temp = html_temp.replace('vt-detections__circle__total">/ 88',
                        f'vt-detections__circle__total">/ {total}')
    html_temp = html_temp.replace('stroke-dashoffset: 276.317022727;',
                        f'stroke-dashoffset: {ratio};')
    html_temp = html_temp.replace('2 security vendors flagged this domain as malicious',
                        f'{detections} security vendors flagged this domain as malicious')
    html_temp = html_temp.replace('virus.net', link_for_report)
    html_temp = html_temp.replace('INAMES CO., LTD.', str(results['malicious']))
    html_temp = html_temp.replace('22 years ago', str(results['suspicious']))
    html_temp = html_temp.replace('9 months ago', str(results['harmless']))
    html_temp = html_temp.replace('undetectedamount', str(results['undetected']))

    with open('temporary.html', 'w') as final:
        final.write(html_temp)
    convert_html_to_png()


def convert_html_to_png():
    # Read the HTML file contents
    with open('temporary.html', "r") as file:
        html_content = file.read()

    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--headless")
    driver = webdriver.Chrome(chrome_options)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(current_dir, "temporary.html")
    driver.get(f"file://{html_path}")
    driver.save_screenshot('image.png')
    driver.quit()
    image = Image.open('image.png')
    crop_dim = (0, 10, 550, 150)
    c_image = image.crop(crop_dim)
    c_image.save('image.png')
    global analysis
    with open('image.png', 'rb') as png:
        analysis = discord.File(png)


client.run(TOKEN)
