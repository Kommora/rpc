package main

import (
	"net"
	"fmt"
	"net/rpc"
	"log"
	"encoding/pem"
	"os"
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"crypto/rand"
	"bytes"
	"errors"
)

type Produto struct{
	Nome, Id, Categoria, Descricao string
	Preco float32
	Quantidade int
}

type Novo struct{
	P1,P2 Produto
}

type Usuario struct {
	Login, Senha []byte
	estado bool
}

var banco map[string]Produto
var usuarios []Usuario

type Crud bool
type User bool

func GerarChavePbPv(){
	pv,_:=rsa.GenerateKey(rand.Reader,2048)
	pvBytes:=x509.MarshalPKCS1PrivateKey(pv)
	pbBytes,err:=x509.MarshalPKIXPublicKey(&pv.PublicKey)
	checkErro(err)

	pvPem:=pem.EncodeToMemory(
		&pem.Block{
			Type:"Private key",
			Bytes:pvBytes},
	)

	pbPem:=pem.EncodeToMemory(
		&pem.Block{
			Type:"Public key",
			Bytes:pbBytes},
	)

	txt,err:=os.Create("servidor/pvB.txt")
	checkErro(err)
	t1:=bufio.NewWriter(txt)
	t1.WriteString(string(pvPem))
	t1.Flush()
	txt.Close()

	txt,err=os.Create("servidor/pbB.txt")
	checkErro(err)
	t1=bufio.NewWriter(txt)
	t1.WriteString(string(pbPem))
	t1.Flush()
	txt.Close()

}

func encriptarMsg(msg string)([]byte,error)  {
	txt,err:=os.Open("cliente/pbA.txt")
	checkErro(err)
	buf:=new(bytes.Buffer)
	buf.ReadFrom(txt)
	keyBuf:=buf.String()

	key,_:=pem.Decode([]byte(keyBuf))
	pbKey,_:=x509.ParsePKIXPublicKey(key.Bytes)

	switch pub := pbKey.(type) {
	case *rsa.PublicKey:
		encript,err:=rsa.EncryptPKCS1v15(rand.Reader,pub,[]byte(msg))
		checkErro(err)
		return encript,nil
	default:
		break
	}
	return nil,errors.New("Impossivel")
}

func decriptar(email []byte,senha []byte)(string,string)  {

	txt,err:=os.Open("servidor/pvB.txt")
	checkErro(err)
	buf:=new(bytes.Buffer)
	buf.ReadFrom(txt)
	keyBuf:=buf.String()

	key,_:=pem.Decode([]byte(keyBuf))
	pvKey,_:=x509.ParsePKCS1PrivateKey(key.Bytes)
	dcEmail,_:=rsa.DecryptPKCS1v15(rand.Reader,pvKey,email)
	dcSenha,_:=rsa.DecryptPKCS1v15(rand.Reader,pvKey,senha)
	return string(dcEmail),string(dcSenha)
}


func (c *Crud) Create(pdt *Produto, reply *bool)error  {
	if _,ok:=banco[pdt.Id];ok{
		*reply=false;
	}else {
		banco[pdt.Id]=*pdt
		*reply=true;
	}
	return nil
}
func (c *Crud) Request(pdt *Produto, reply *Produto)error  {
	if _,ok:=banco[pdt.Id];ok{
		*reply=banco[pdt.Id];
	}else {
		*reply=Produto{};
	}
	return nil
}
func (c *Crud) Update(pdt *Novo, reply *bool)error  {
	if _,ok:=banco[pdt.P1.Id];ok{
		if pdt.P1.Id!=pdt.P2.Id{
			delete(banco,pdt.P1.Id)
			banco[pdt.P2.Id]=pdt.P2
		}else {
			banco[pdt.P1.Id]=pdt.P2
		}
		*reply=true
	}else {
		*reply=false
	}
	return nil
}
func (c *Crud) Delete(pdt *Produto, reply *bool)error  {
	if _,ok:=banco[pdt.Id];ok{
		delete(banco,pdt.Id)
		*reply=true
	}else {
		*reply=false
	}
	return nil
}

func (u *User) Login(args *Usuario, replay *[]byte)error  {
	a,b:=decriptar(args.Login,args.Senha)
	for i,usuario:=range usuarios{
		if string(usuario.Login)==a && string(usuario.Senha)==b {
			c,err:=encriptarMsg("ok")
			checkErro(err)
			usuarios[i].estado=true
			*replay=c
			break
		}
	}
	return nil
}

func (u *Crud) Deslogar(args *Usuario, replay *bool)error  {
	for i,usuario:=range usuarios{
		if string(usuario.Login)==string(args.Login) && string(usuario.Senha)==string(args.Senha) {
			usuarios[i].estado=false
			*replay=true
			break
		}
	}
	return nil
}


func main() {
	rpc.Register(new(Crud))
	rpc.Register(new(User))

	GerarChavePbPv()
	
	banco = make(map[string]Produto)
	usuarios = make([]Usuario,10)
	
	usuarios=append(usuarios, Usuario{[]byte("afonso@lindo.belo"),[]byte("6996"),false})
	
	ln,err:=net.Listen("tcp","localhost:5555")
	checkErro(err)
	
	fmt.Println("conexao aberta")
	for {
		con,err:=ln.Accept();
		if err!=nil {
			fmt.Println(err)
			continue
		}
		fmt.Println("conectou")
		rpc.ServeConn(con)
	}
}

func checkErro(err error)  {
	if err!=nil{
		log.Fatal("error:", err)
	}
}