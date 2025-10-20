import discord
from discord import app_commands
from discord.ui import View, Button
import imagehash
from PIL import Image
import requests
from io import BytesIO
import json
import os
from datetime import timedelta, datetime
from dotenv import load_dotenv
import aiohttp
import asyncio

load_dotenv()

# Configuration
HASH_FILE = 'scam_hashes.json'
IMAGES_FOLDER = 'images'
TEMP_FOLDER = 'temp'
HASH_THRESHOLD = 8
TIMEOUT_DURATION = timedelta(days=7)
ITEMS_PER_PAGE = 10

intents = discord.Intents.default()
intents.message_content = True
intents.members = True

class ScamBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
    
    async def setup_hook(self):
        await self.tree.sync()

client = ScamBot()

@client.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.CheckFailure):
        return
    else:
        # Log other errors
        print(f"Error in command {interaction.command.name}: {error}")
        if not interaction.response.is_done():
            await interaction.response.send_message('❌ An error occurred while executing this command.', ephemeral=True)

os.makedirs(IMAGES_FOLDER, exist_ok=True)
os.makedirs(TEMP_FOLDER, exist_ok=True)


def load_hashes():
    try:
        with open(HASH_FILE, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_hashes(hashes):
    with open(HASH_FILE, 'w') as f:
        json.dump(hashes, f, indent=2)


def get_next_name(base_name):
    # Get the next available name with incrementing suffix
    hashes = load_hashes()
    existing_names = [item['name'] for item in hashes]
    
    counter = 1
    while True:
        new_name = f"{base_name}_{counter}"
        if new_name not in existing_names:
            return new_name
        counter += 1


async def download_image(url, path):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    with open(path, 'wb') as f:
                        f.write(await resp.read())
                    return True
    except Exception as e:
        print(f"Error downloading image: {e}")
    return False


def get_image_hash(image_url):
    # Calculate perceptual hash of an image URL
    try:
        response = requests.get(image_url, timeout=10)
        response.raise_for_status()
        
        img = Image.open(BytesIO(response.content))
        phash = imagehash.phash(img, hash_size=16)
        return str(phash)
    except Exception as e:
        print(f"Error hashing image: {e}")
        return None


def is_scam_image(image_url):
    try:
        image_hash = get_image_hash(image_url)
        if not image_hash:
            return {'match': False, 'error': True}
        
        known_hashes = load_hashes()
        image_hash_obj = imagehash.hex_to_hash(image_hash)
        
        for scam_entry in known_hashes:
            for hash_entry in scam_entry['hashes']:
                known_hash_obj = imagehash.hex_to_hash(hash_entry['hash'])
                distance = image_hash_obj - known_hash_obj
                
                if distance <= HASH_THRESHOLD:
                    return {
                        'match': True,
                        'scam_name': scam_entry['name'],
                        'hash_entry': hash_entry,
                        'distance': distance,
                        'scam_data': scam_entry
                    }
        
        return {'match': False}
    except Exception as e:
        print(f"Error processing image: {e}")
        return {'match': False, 'error': True}


async def get_log_channel(guild):
    return discord.utils.get(guild.text_channels, name='scam-automod-logs')


class RemoveTimeoutButton(View):
    def __init__(self, user_id, guild):
        super().__init__(timeout=None)
        self.user_id = user_id
        self.guild = guild
    
    @discord.ui.button(label='Remove Timeout', style=discord.ButtonStyle.success, emoji='✅')
    async def remove_timeout(self, interaction: discord.Interaction, button: Button):
        # Check if user has Staff role
        staff_role = discord.utils.get(interaction.guild.roles, name='Staff')
        if not staff_role or staff_role not in interaction.user.roles:
            await interaction.response.send_message('❌ You need the Staff role to use this button.', ephemeral=True)
            return
        
        # Remove timeout
        try:
            member = self.guild.get_member(self.user_id)
            if member:
                await member.timeout(None, reason=f'Timeout removed by {interaction.user} - False positive')
                
                button.disabled = True
                button.label = 'Timeout Removed'
                button.style = discord.ButtonStyle.gray
                await interaction.response.edit_message(view=self)
                
                await interaction.followup.send(f'✅ Timeout removed from {member.mention}', ephemeral=True)
            else:
                await interaction.response.send_message('❌ User not found in server.', ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f'❌ Error removing timeout: {str(e)}', ephemeral=True)


async def log_scam_detection(guild, user, message, match_info, detected_image_url):
    try:
        log_channel = await get_log_channel(guild)
        if not log_channel:
            print('Warning: #scam-automod-logs channel not found')
            return
        
        embed = discord.Embed(
            title='🚨 Scam Image Detected',
            color=discord.Color.red(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='Scam Name', value=match_info['scam_name'], inline=True)
        embed.add_field(name='User', value=f'{user.mention} ({user.id})', inline=True)
        embed.add_field(name='Channel', value=message.channel.mention, inline=True)
        embed.add_field(
            name='Action Taken',
            value='Message deleted, user timed out for 1 week',
            inline=False
        )
        embed.add_field(
            name='Hash Distance',
            value=f"{match_info['distance']} (threshold: {HASH_THRESHOLD})",
            inline=True
        )
        embed.set_footer(text='Detected Image ⬇️')
        
        await log_channel.send(embed=embed)
        
        # Download detected image to temp folder
        import uuid
        temp_filename = f"{uuid.uuid4()}.png"
        temp_path = os.path.join(TEMP_FOLDER, temp_filename)
        
        await download_image(detected_image_url, temp_path)
        
        # Send detected image
        if os.path.exists(temp_path):
            await log_channel.send(content="**Detected Image:**", file=discord.File(temp_path))
            os.remove(temp_path)
        
        # Send stored image
        stored_image_path = match_info['hash_entry']['image_path']
        if os.path.exists(stored_image_path):
            await log_channel.send(content="**Stored Image (Database):**", file=discord.File(stored_image_path))
        
        # Add Remove Timeout button
        view = RemoveTimeoutButton(user.id, guild)
        await log_channel.send("⬇️ False positive? Remove timeout:", view=view)
        
    except Exception as e:
        print(f"Error logging to channel: {e}")


async def check_and_moderate_message(message):
    # Skip if in scam-automod-logs channel
    if message.channel.name == 'scam-automod-logs':
        return False
    
    image_urls = []
    
    for attachment in message.attachments:
        if attachment.content_type and attachment.content_type.startswith('image/'):
            image_urls.append(attachment.url)
    
    for embed in message.embeds:
        if embed.image:
            image_urls.append(embed.image.url)
        if embed.thumbnail:
            image_urls.append(embed.thumbnail.url)
    
    for image_url in image_urls:
        result = is_scam_image(image_url)
        
        if result['match']:
            try:
                await message.delete()
                
                member = message.guild.get_member(message.author.id)
                if member:
                    await member.timeout(
                        TIMEOUT_DURATION,
                        reason='Posted scam image detected by automod'
                    )
                
                await log_scam_detection(message.guild, message.author, message, result, image_url)
                
                print(f"Scam detected from {message.author}, message deleted and user timed out")
                return True
            except Exception as e:
                print(f"Error taking action: {e}")
            break
    
    return False


async def add_scam_logic(guild, user, replied_message, scam_name):
    log_channel = await get_log_channel(guild)
    
    image_urls = []
    for attachment in replied_message.attachments:
        if attachment.content_type and attachment.content_type.startswith('image/'):
            image_urls.append(attachment.url)
    
    for embed in replied_message.embeds:
        if embed.image:
            image_urls.append(embed.image.url)
        if embed.thumbnail:
            image_urls.append(embed.thumbnail.url)
    
    if not image_urls:
        if log_channel:
            await log_channel.send('❌ The message does not contain any images.')
        return None, '❌ The message does not contain any images.'
    
    full_name = get_next_name(scam_name)
    
    image_folder = os.path.join(IMAGES_FOLDER, full_name)
    os.makedirs(image_folder, exist_ok=True)
    
    hashes_list = []
    for idx, image_url in enumerate(image_urls):
        image_hash = get_image_hash(image_url)
        if not image_hash:
            continue
        
        image_path = os.path.join(image_folder, f"{idx}.png")
        await download_image(image_url, image_path)
        
        hashes_list.append({
            'hash': image_hash,
            'image_path': image_path
        })
    
    if not hashes_list:
        if log_channel:
            await log_channel.send('❌ Error processing images.')
        return None, '❌ Error processing images.'
    
    hashes = load_hashes()
    hashes.append({
        'name': full_name,
        'hashes': hashes_list,
        'addedBy': str(user),
        'addedAt': datetime.utcnow().isoformat()
    })
    save_hashes(hashes)
    
    # Timeout the user who posted the scam
    try:
        member = replied_message.guild.get_member(replied_message.author.id)
        if member and not member.bot:
            await member.timeout(
                TIMEOUT_DURATION,
                reason=f'Posted scam image: {full_name}'
            )
    except Exception as e:
        print(f"Error timing out user: {e}")
    
    try:
        await replied_message.delete()
    except:
        pass
    
    # Log to channel
    if log_channel:
        embed = discord.Embed(
            title='✅ Scam Added to Database',
            color=discord.Color.green(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name='Scam Name', value=full_name, inline=True)
        embed.add_field(name='Added By', value=str(user), inline=True)
        embed.add_field(name='Images', value=str(len(hashes_list)), inline=True)
        embed.add_field(name='Total Scams', value=str(len(hashes)), inline=True)
        
        await log_channel.send(embed=embed)
        
        for hash_entry in hashes_list:
            if os.path.exists(hash_entry['image_path']):
                await log_channel.send(file=discord.File(hash_entry['image_path']))
    
    return full_name, f'✅ Scam "{full_name}" added successfully.'


class DeleteButton(View):
    def __init__(self, messages_to_delete):
        super().__init__(timeout=None)
        self.messages_to_delete = messages_to_delete
    
    @discord.ui.button(label='Delete This Message', style=discord.ButtonStyle.danger)
    async def delete_button(self, interaction: discord.Interaction, button: Button):
        for msg in self.messages_to_delete:
            try:
                await msg.delete()
            except:
                pass
        await interaction.response.send_message('✅ Messages deleted.', ephemeral=True)


class PaginationView(View):
    def __init__(self, hashes, current_page=1):
        super().__init__(timeout=300)
        self.hashes = hashes
        self.current_page = current_page
        self.total_pages = (len(hashes) + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE
        
        self.update_buttons()
    
    def update_buttons(self):
        self.first_page.disabled = self.current_page == 1
        self.prev_page.disabled = self.current_page == 1
        self.next_page.disabled = self.current_page == self.total_pages
        self.last_page.disabled = self.current_page == self.total_pages
    
    def get_embed(self):
        start_idx = (self.current_page - 1) * ITEMS_PER_PAGE
        end_idx = start_idx + ITEMS_PER_PAGE
        page_items = self.hashes[start_idx:end_idx]
        
        embed = discord.Embed(
            title=f'📋 Scam Database (Page {self.current_page}/{self.total_pages})',
            description=f'Total scams: {len(self.hashes)}',
            color=discord.Color.blue()
        )
        
        for item in page_items:
            added_date = datetime.fromisoformat(item['addedAt']).strftime('%Y-%m-%d %H:%M')
            embed.add_field(
                name=item['name'],
                value=f"Images: {len(item['hashes'])} | Added by: {item['addedBy']}\nDate: {added_date}",
                inline=False
            )
        
        embed.set_footer(text=f'Page {self.current_page} of {self.total_pages}')
        return embed
    
    @discord.ui.button(label='⏮️', style=discord.ButtonStyle.gray)
    async def first_page(self, interaction: discord.Interaction, button: Button):
        self.current_page = 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.get_embed(), view=self)
    
    @discord.ui.button(label='◀️', style=discord.ButtonStyle.primary)
    async def prev_page(self, interaction: discord.Interaction, button: Button):
        self.current_page -= 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.get_embed(), view=self)
    
    @discord.ui.button(label='▶️', style=discord.ButtonStyle.primary)
    async def next_page(self, interaction: discord.Interaction, button: Button):
        self.current_page += 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.get_embed(), view=self)
    
    @discord.ui.button(label='⏭️', style=discord.ButtonStyle.gray)
    async def last_page(self, interaction: discord.Interaction, button: Button):
        self.current_page = self.total_pages
        self.update_buttons()
        await interaction.response.edit_message(embed=self.get_embed(), view=self)
    
    @discord.ui.button(label='🗑️ Delete', style=discord.ButtonStyle.danger)
    async def delete_message(self, interaction: discord.Interaction, button: Button):
        await interaction.message.delete()
        await interaction.response.send_message('✅ Message deleted.', ephemeral=True)


def has_staff_role():
    async def predicate(interaction: discord.Interaction) -> bool:
        staff_role = discord.utils.get(interaction.guild.roles, name='Staff')
        if not staff_role or staff_role not in interaction.user.roles:
            await interaction.response.send_message('❌ You need the Staff role to use this command.', ephemeral=True)
            return False
        return True
    return app_commands.check(predicate)


@client.event
async def on_ready():
    print(f'✅ Bot logged in as {client.user}')
    print(f'📊 Using hash threshold: {HASH_THRESHOLD}')
    print(f'🔄 Commands synced')


@client.event
async def on_message(message):
    if message.author.bot or not message.guild:
        return
    
    await check_and_moderate_message(message)


class ScamNameModal(discord.ui.Modal, title='Add Scam Image'):
    scam_name = discord.ui.TextInput(
        label='Scam Name',
        placeholder='e.g., Crypto, Nitro, etc.',
        required=True,
        max_length=50
    )
    
    def __init__(self, target_message):
        super().__init__()
        self.target_message = target_message
    
    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        
        scam_name = self.scam_name.value.strip()
        
        full_name, result_msg = await add_scam_logic(
            interaction.guild,
            interaction.user,
            self.target_message,
            scam_name
        )
        
        await interaction.followup.send('✅ Command executed. Check logs channel.', ephemeral=True)


@client.tree.context_menu(name='Add Scam Image')
async def add_scam_context(interaction: discord.Interaction, message: discord.Message):
    staff_role = discord.utils.get(interaction.guild.roles, name='Staff')
    if not staff_role or staff_role not in interaction.user.roles:
        await interaction.response.send_message(
            '❌ You need the Staff role to use this command.',
            ephemeral=True
        )
        return
    
    modal = ScamNameModal(message)
    await interaction.response.send_modal(modal)


@client.tree.command(name='listscams', description='List all scams in the database')
@app_commands.describe(page='Page number (default: 1)')
@app_commands.default_permissions(moderate_members=True)
@has_staff_role()
async def listscams_slash(interaction: discord.Interaction, page: int = 1):
    log_channel = await get_log_channel(interaction.guild)
    if not log_channel:
        await interaction.response.send_message('❌ #scam-automod-logs channel not found.', ephemeral=True)
        return
    
    hashes = load_hashes()
    if not hashes:
        await log_channel.send('No scams in database yet.')
        await interaction.response.send_message('✅ Command executed. Check logs channel.', ephemeral=True)
        return
    
    view = PaginationView(hashes, current_page=page)
    
    await log_channel.send(embed=view.get_embed(), view=view)
    await interaction.response.send_message('✅ Command executed. Check logs channel.', ephemeral=True)


@client.tree.command(name='removescam', description='Remove a scam from the database')
@app_commands.describe(name='The exact name of the scam to remove')
@app_commands.default_permissions(moderate_members=True)
@has_staff_role()
async def removescam_slash(interaction: discord.Interaction, name: str):
    log_channel = await get_log_channel(interaction.guild)
    if not log_channel:
        await interaction.response.send_message('❌ #scam-automod-logs channel not found.', ephemeral=True)
        return
    
    hashes = load_hashes()
    scam_data = None
    scam_idx = None
    
    for idx, item in enumerate(hashes):
        if item['name'] == name:
            scam_data = item
            scam_idx = idx
            break
    
    if not scam_data:
        await log_channel.send(f'❌ Scam "{name}" not found in database.')
        await interaction.response.send_message('✅ Command executed. Check logs channel.', ephemeral=True)
        return
    
    added_date = datetime.fromisoformat(scam_data['addedAt']).strftime('%Y-%m-%d %H:%M:%S')
    
    embed = discord.Embed(
        title=f'🗑️ Removed Scam: {name}',
        color=discord.Color.orange(),
        timestamp=datetime.utcnow()
    )
    embed.add_field(name='Added By', value=scam_data['addedBy'], inline=True)
    embed.add_field(name='Date Added', value=added_date, inline=True)
    embed.add_field(name='Number of Images', value=str(len(scam_data['hashes'])), inline=True)
    
    await log_channel.send(embed=embed)
    
    for hash_entry in scam_data['hashes']:
        if os.path.exists(hash_entry['image_path']):
            await log_channel.send(file=discord.File(hash_entry['image_path']))
    
    image_folder = os.path.join(IMAGES_FOLDER, name)
    if os.path.exists(image_folder):
        import shutil
        shutil.rmtree(image_folder)
    
    hashes.pop(scam_idx)
    save_hashes(hashes)
    
    await interaction.response.send_message('✅ Command executed. Check logs channel.', ephemeral=True)


@client.tree.command(name='viewscam', description='View details about a scam')
@app_commands.describe(name='The exact name of the scam to view')
@app_commands.default_permissions(moderate_members=True)
@has_staff_role()
async def viewscam_slash(interaction: discord.Interaction, name: str):
    log_channel = await get_log_channel(interaction.guild)
    if not log_channel:
        await interaction.response.send_message('❌ #scam-automod-logs channel not found.', ephemeral=True)
        return
    
    hashes = load_hashes()
    scam_data = None
    
    for item in hashes:
        if item['name'] == name:
            scam_data = item
            break
    
    if not scam_data:
        await log_channel.send(f'❌ Scam "{name}" not found in database.')
        await interaction.response.send_message('✅ Command executed. Check logs channel.', ephemeral=True)
        return
    
    added_date = datetime.fromisoformat(scam_data['addedAt']).strftime('%Y-%m-%d %H:%M:%S')
    
    embed = discord.Embed(
        title=f'🔍 Scam Details: {name}',
        color=discord.Color.blue(),
        timestamp=datetime.utcnow()
    )
    embed.add_field(name='Added By', value=scam_data['addedBy'], inline=True)
    embed.add_field(name='Date Added', value=added_date, inline=True)
    embed.add_field(name='Number of Images', value=str(len(scam_data['hashes'])), inline=True)
    
    messages_to_delete = []
    embed_msg = await log_channel.send(embed=embed)
    messages_to_delete.append(embed_msg)
    
    for hash_entry in scam_data['hashes']:
        if os.path.exists(hash_entry['image_path']):
            img_msg = await log_channel.send(file=discord.File(hash_entry['image_path']))
            messages_to_delete.append(img_msg)
    
    view = DeleteButton(messages_to_delete)
    delete_btn_msg = await log_channel.send("⬇️ Delete all messages above", view=view)
    messages_to_delete.append(delete_btn_msg)
    
    await interaction.response.send_message('✅ Command executed. Check logs channel.', ephemeral=True)


client.run(os.getenv('BOT_TOKEN'))
