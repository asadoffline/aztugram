require('dotenv').config();
const express=require('express'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),nodemailer=require('nodemailer');
const {JWT_SECRET,GMAIL_USER,GMAIL_APP_PASSWORD,ANTHROPIC_API_KEY,AI_MODEL='claude-haiku-5-5',PORT=3000}=process.env;
const DB_FILE=process.env.DB_FILE||path.join(__dirname,'data','db.json');
if(!JWT_SECRET){console.error('JWT_SECRET təyin edilməyib (.env faylına bax)');process.exit(1)}
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'20kb'}));
/* CORS: sayt başqa domendədirsə (məs. GitHub Pages). ALLOWED_ORIGIN=https://istifadeci.github.io */
const ORIGINS=(process.env.ALLOWED_ORIGIN||'').split(',').map(x=>x.trim()).filter(Boolean);
app.use('/api',(q,s,nx)=>{const o=q.headers.origin;
  if(o&&ORIGINS.includes(o)){s.set({'Access-Control-Allow-Origin':o,'Vary':'Origin','Access-Control-Allow-Headers':'Content-Type,Authorization','Access-Control-Allow-Methods':'GET,POST,DELETE,OPTIONS'})}
  if(q.method==='OPTIONS')return s.sendStatus(204);nx()});

/* Sadə JSON verilənlər bazası */
fs.mkdirSync(path.dirname(DB_FILE),{recursive:true});
let db={users:[],events:[]};
try{db=JSON.parse(fs.readFileSync(DB_FILE,'utf8'))}catch(e){}
const persist=()=>{fs.writeFileSync(DB_FILE+'.tmp',JSON.stringify(db));fs.renameSync(DB_FILE+'.tmp',DB_FILE)};

/* Sürət limiti */
const hits=new Map();
const limit=(n,ms)=>(q,s,nx)=>{const k=q.path+(q.user?q.user.id:q.ip),t=Date.now(),a=(hits.get(k)||[]).filter(x=>t-x<ms);
  if(a.length>=n)return s.status(429).json({error:'Çox sorğu göndərdin, bir az gözlə.'});a.push(t);hits.set(k,a);nx()};

const mailer=nodemailer.createTransport({service:'gmail',auth:{user:GMAIL_USER,pass:GMAIL_APP_PASSWORD}});
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
async function sendCode(u){
  const code=String(crypto.randomInt(100000,1000000));
  u.code=sha(code);u.codeExp=Date.now()+10*60*1000;u.tries=0;persist();
  await mailer.sendMail({from:`AZTUGRAM <${GMAIL_USER}>`,to:u.email,subject:'AZTUGRAM təsdiq kodu',
    text:`Salam ${u.name},\n\nAZTUGRAM təsdiq kodun: ${code}\nKod 10 dəqiqə etibarlıdır.\n\nBu sorğunu sən göndərməmisənsə, mesajı nəzərə alma.`});
}
const pub=u=>({id:u.id,name:u.name,email:u.email});
const token=u=>jwt.sign({id:u.id},JWT_SECRET,{expiresIn:'30d'});
function auth(q,s,nx){
  try{const p=jwt.verify((q.headers.authorization||'').replace('Bearer ',''),JWT_SECRET);
    const u=db.users.find(x=>x.id===p.id&&x.verified);if(!u)throw 0;q.user=u;nx()}
  catch(e){s.status(401).json({error:'Əvvəlcə daxil ol.'})}
}
const wrap=f=>(q,s)=>f(q,s).catch(e=>{console.error(e);s.status(500).json({error:'Server xətası. Bir az sonra yenə yoxla.'})});

app.post('/api/register',limit(8,3600e3),wrap(async(q,s)=>{
  const name=String(q.body.name||'').trim().slice(0,30),email=String(q.body.email||'').trim().toLowerCase(),pw=String(q.body.password||'');
  if(name.length<2)return s.status(400).json({error:'Ad ən azı 2 hərf olmalıdır.'});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return s.status(400).json({error:'Email düzgün deyil.'});
  if(pw.length<6)return s.status(400).json({error:'Şifrə ən azı 6 simvol olmalıdır.'});
  let u=db.users.find(x=>x.email===email);
  if(u&&u.verified)return s.status(409).json({error:'Bu email artıq qeydiyyatdadır. Daxil ol.'});
  if(!u){u={id:crypto.randomUUID(),email,verified:false};db.users.push(u)}
  u.name=name;u.hash=await bcrypt.hash(pw,10);
  await sendCode(u);
  s.json({message:'Təsdiq kodu emailinə göndərildi. Spam qovluğuna da bax.'});
}));
app.post('/api/verify',limit(20,3600e3),wrap(async(q,s)=>{
  const u=db.users.find(x=>x.email===String(q.body.email||'').trim().toLowerCase());
  if(!u||!u.code)return s.status(400).json({error:'Kod tapılmadı. Yenidən qeydiyyatdan keç.'});
  if(Date.now()>u.codeExp||u.tries>=5)return s.status(400).json({error:'Kodun vaxtı bitib və ya cəhd limiti dolub. Yenidən daxil olub yeni kod al.'});
  u.tries++;
  if(sha(String(q.body.code||'').trim())!==u.code){persist();return s.status(400).json({error:'Kod yanlışdır.'})}
  u.verified=true;u.code=null;persist();
  s.json({token:token(u),user:pub(u)});
}));
app.post('/api/login',limit(15,900e3),wrap(async(q,s)=>{
  const u=db.users.find(x=>x.email===String(q.body.email||'').trim().toLowerCase());
  if(!u||!(await bcrypt.compare(String(q.body.password||''),u.hash)))return s.status(401).json({error:'Email və ya şifrə yanlışdır.'});
  if(!u.verified){await sendCode(u);return s.status(403).json({needVerify:true,error:'Email təsdiqlənməyib. Yeni kod göndərdik.'})}
  s.json({token:token(u),user:pub(u)});
}));
app.get('/api/me',auth,(q,s)=>s.json({user:pub(q.user)}));

/* Tədbirlər */
app.get('/api/events',(q,s)=>{
  const names=Object.fromEntries(db.users.map(u=>[u.id,u.name]));
  s.json({events:db.events.slice().sort((a,b)=>a.date.localeCompare(b.date)).map(e=>({...e,author:names[e.uid]||'Tələbə'}))});
});
app.post('/api/events',auth,limit(10,3600e3),wrap(async(q,s)=>{
  const b=q.body,e={id:crypto.randomUUID(),uid:q.user.id,title:String(b.title||'').trim().slice(0,80),
    date:String(b.date||''),place:String(b.place||'').trim().slice(0,60),desc:String(b.desc||'').trim().slice(0,300)};
  if(!e.title||!/^\d{4}-\d{2}-\d{2}$/.test(e.date)||!e.place)return s.status(400).json({error:'Ad, tarix və yer mütləqdir.'});
  if(db.events.length>=500)return s.status(400).json({error:'Tədbir limiti dolub.'});
  db.events.push(e);persist();s.json({event:e});
}));
app.delete('/api/events/:id',auth,(q,s)=>{
  const i=db.events.findIndex(e=>e.id===q.params.id&&e.uid===q.user.id);
  if(i<0)return s.status(404).json({error:'Tapılmadı və ya səndə icazə yoxdur.'});
  db.events.splice(i,1);persist();s.json({ok:true});
});

/* AzTU AI */
const SYSTEM=`Sən AzTU AI-san: AZTUGRAM saytında Azərbaycan Texniki Universiteti (AzTU) tələbələrinə kömək edən köməkçisən. Universitet, qəbul, təhsil, bal sistemi, fakültələr, kampus və tələbə həyatı haqqında suallara cavab ver. Dəqiq bilmədiyin məlumatı (qəbul balları, tarixlər, qiymətlər, ad-soyadlar, cədvəllər) uydurma; bunu açıq de və rəsmi aztu.edu.az saytına yönləndir. Qısa və aydın cavab ver, istifadəçi hansı dildə yazırsa o dildə. Mövzudan kənar suallarda nəzakətlə qeyd et ki, yalnız AzTU ilə bağlı kömək edirsən. Sən rəsmi AzTU nümayəndəsi deyilsən.`;
app.post('/api/ai',auth,limit(20,3600e3),wrap(async(q,s)=>{
  if(!ANTHROPIC_API_KEY)return s.status(503).json({error:'AI hələ qoşulmayıb.'});
  let m=(Array.isArray(q.body.messages)?q.body.messages:[]).slice(-9)
    .filter(x=>x&&['user','assistant'].includes(x.role)&&typeof x.content==='string'&&x.content.trim())
    .map(x=>({role:x.role,content:x.content.slice(0,1000)}));
  while(m.length&&m[0].role!=='user')m.shift();
  if(!m.length||m[m.length-1].role!=='user')return s.status(400).json({error:'Sual boşdur.'});
  const r=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',
    headers:{'content-type':'application/json','x-api-key':ANTHROPIC_API_KEY,'anthropic-version':'2023-06-01'},
    body:JSON.stringify({model:AI_MODEL,max_tokens:600,system:SYSTEM,messages:m})});
  const j=await r.json();
  if(!r.ok){console.error(j);return s.status(502).json({error:'AI cavab verə bilmədi.'})}
  s.json({reply:(j.content||[]).map(c=>c.text||'').join('')});
}));

app.use(express.static(path.join(__dirname,'public')));
app.listen(PORT,()=>console.log('AZTUGRAM işləyir: port '+PORT));
