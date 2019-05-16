#include "smartnet_parser.h"
#include "../formatter.h"

using namespace std;
SmartnetParser::SmartnetParser()
{
  numStacked = 0;
  numConsumed = 0;
}

double SmartnetParser::getfreq(int cmd, System *sys)
{
  double freq = 0.0;
  std::string band = sys->get_bandplan();
  if (sys->get_bandfreq() == 800)
  {
    /*
          BANDPLAN 800Mhz:
          800_standard * Is default base plan
          800_splinter
          800_reband
        */
    if (cmd < 0 || cmd > 0x3FE)
      return freq;
    if (cmd <= 0x2CF)
    {
      if (band == "800_reband" && cmd >= 0x1B8 && cmd <= 0x22F)
      { /* Re Banded Site */
        freq = 851.0250 + (0.025 * ((double)(cmd - 0x1B8)));
      }
      else if (band == "800_splinter" && cmd <= 0x257)
      { /* Splinter Site */
        freq = 851.0 + (0.025 * ((double)cmd));
      }
      else
      {
        freq = 851.0125 + (0.025 * ((double)cmd));
      }
    }
    else if (cmd <= 0x2f7)
    {
      freq = 866.0000 + (0.025 * ((double)(cmd - 0x2D0)));
    }
    else if (cmd >= 0x32F && cmd <= 0x33F)
    {
      freq = 867.0000 + (0.025 * ((double)(cmd - 0x32F)));
    }
    else if (cmd == 0x3BE)
    {
      freq = 868.9750;
    }
    else if (cmd >= 0x3C1 && cmd <= 0x3FE)
    {
      freq = 867.4250 + (0.025 * ((double)(cmd - 0x3C1)));
    }
  }
  else if (sys->get_bandfreq() == 400)
  {
    double high_cmd = sys->get_bandplan_offset() + (sys->get_bandplan_high() - sys->get_bandplan_base()) / sys->get_bandplan_spacing();

    if ((cmd >= sys->get_bandplan_offset()) && (cmd < high_cmd))
    {
      freq = sys->get_bandplan_base() + (sys->get_bandplan_spacing() * (cmd - sys->get_bandplan_offset()));
    }
    //cout << "Orig: " <<fixed <<test_freq << " Freq: " << freq << endl;
  }
  return freq * 1000000;
}

std::vector<TrunkMessage> SmartnetParser::parse_message(std::string s, System *sys)
{
  std::vector<TrunkMessage> messages;
  TrunkMessage message;

  message.sys_num = sys->get_sys_num();
  message.sys_id = 0;
  message.message_type = UNKNOWN;
  message.encrypted = false;
  message.emergency = false;
  message.source = 0;
  message.freq = 0;
  message.phase2_tdma = false;
  message.tdma_slot = 0;

  std::vector<std::string> x;
  boost::split(x, s, boost::is_any_of(","), boost::token_compress_on);

  if (x.size() < 3)
  {
    BOOST_LOG_TRIVIAL(error) << "SmartNet Parser recieved invalid message." << x.size();
    return messages;
  }

  struct osw_stru bosw;
  bosw.full_address = atoi(x[0].c_str());
  bosw.address = bosw.full_address & 0xFFF0;
  bosw.id = bosw.address;
  bosw.status = bosw.full_address & 0x000F;
  bosw.grp = atoi(x[1].c_str());
  bosw.cmd = atoi(x[2].c_str());

  cout.precision(0);

  // maintain a sliding stack of 5 OSWs

  switch (numStacked) // note: drop-thru is intentional!
  {
  case 5:
  case 4:
    stack[4] = stack[3];

  case 3:
    stack[3] = stack[2];

  case 2:
    stack[2] = stack[1];

  case 1:
    stack[1] = stack[0];

  case 0:
    stack[0] = bosw;
    break;

  default:
    BOOST_LOG_TRIVIAL(info) << "corrupt value for nstacked" << endl;
    break;
  }

  if (numStacked < 5)
  {
    ++numStacked;
  }

  x.clear();
  vector<string>().swap(x);

  BOOST_LOG_TRIVIAL(trace) <<
  "[ CMD: " << (boost::format("0x%03x") % stack[0].cmd) << " ]\t" <<
  "[ GRP: " << stack[0].grp << " ]\t" <<
  "[ ADDR: " << (boost::format("0x%04x") % stack[0].full_address) << " ]\t" <<
  "[ TG: " << dec << stack[0].address << " ]\t" <<
  "[ STATUS: " << dec << stack[0].status << " ]";

  // If our cmd is a frequency in this system, then we're probably dealing with
  // a group call update or a group call grant
  if (stack[0].grp && getfreq(stack[0].cmd, sys))
  {
    // Look up the stack to see if this is a grant. cmd will be 0x308 for an analog grant,
    // or 0x321 for a digital grant, or an input freq (0x000-0x17B) for a UHF/VHF system
    // TODO: Look further up the stack if the next message is one that is permitted to interrupt
    if (
      (sys->get_bandfreq() == 800 && (stack[1].cmd == OSW_FIRST_NORMAL || stack[1].cmd == OSW_FIRST_ASTRO))
      || (sys->get_bandfreq() == 400 && stack[1].cmd <= 0x17B)
    )
    {
      //cout << "NEW GRANT!! CMD1: " << fixed << hex << stack[1].cmd << " 0add: " << dec <<  stack[0].address << " 0full_add: " << stack[0].full_address  << " 1add: " << stack[1].address << " 1full_add: " << stack[1].full_address  << endl;
      message.message_type = GRANT;
      message.source = stack[1].full_address;
    }
    /* else if (stack[2].cmd == OSW_SECOND_NORMAL)
    {
      BOOST_LOG_TRIVIAL(info) << "Non-Grant with source 0x" << stack[1].full_address << " " << std::dec << stack[1].full_address << " on TG 0x" << std::hex << stack[0].full_address << " " << std::dec << stack[0].full_address;
      message.message_type = UNKNOWN;
      message.source = 0;

      return messages;
    } */
    else
    {
      message.message_type = UPDATE;
      //cout << "NEW UPDATE [ Freq: " << fixed << getfreq(stack[0].cmd) << " CMD0: " << hex << stack[0].cmd << " CMD1: " << hex << stack[1].cmd << " CMD2: " << hex << stack[2].cmd   << " ] " << " Grp: " << stack[0].grp << " Grp1: " << stack[1].grp << endl;
    }

    message.talkgroup = stack[0].address;
    message.freq = getfreq(stack[0].cmd, sys);

    if ((stack[0].status == 2) || (stack[0].status == 4) || (stack[0].status == 5))
    {
      message.emergency = true;
    }
    else if (stack[0].status == 3)
    {
      // Patched call
    }
    else if (stack[0].status >= 8)
    { // Ignore DES Encryption
      message.encrypted = true;
    }

    messages.push_back(message);
  }

  return messages;
}
